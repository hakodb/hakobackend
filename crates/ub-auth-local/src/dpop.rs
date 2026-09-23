//! DPoP (RFC 9449): proof-of-possession untuk access token lokal.
//!
//! Token curian tidak bisa dipakai tanpa private key pemiliknya. Mendukung
//! RSA (RS256) + EC (ES256/ES384); OKP/mTLS menyusul. Batasan terdokumentasi:
//! tanpa `nonce` server (jendela iat + cache jti sebagai anti-replay),
//! tanpa validasi kurva EC eksplisit (didelegasikan ke jsonwebtoken).

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// iat boleh 5 mnt lalu s/d 30 dtk ke depan (tanpa nonce: jendela sempit + jti).
pub const IAT_PAST_SECS: u64 = 300;
pub const IAT_FUTURE_SECS: u64 = 30;
const REPLAY_TTL: Duration = Duration::from_secs(IAT_PAST_SECS + 60);
const REPLAY_CAP: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpopMode {
    Off,
    Accept,
    Require,
}

impl DpopMode {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "off" => Ok(Self::Off),
            "accept" => Ok(Self::Accept),
            "require" => Ok(Self::Require),
            other => Err(format!("dpop `{other}` tak dikenal (off|accept|require)")),
        }
    }

    pub fn from_env() -> Self {
        std::env::var("UB_LOCAL_DPOP").ok().and_then(|v| Self::parse(&v).ok()).unwrap_or(Self::Off)
    }
}

#[derive(Debug, serde::Deserialize)]
struct ProofHeader {
    alg: String,
    #[serde(default)]
    typ: Option<String>,
    #[serde(default)]
    kid: Option<String>,
    jwk: serde_json::Value,
}

#[derive(Debug, serde::Deserialize)]
struct ProofClaims {
    jti: String,
    htm: String,
    htu: String,
    iat: u64,
    ath: Option<String>,
}

fn b64d(s: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD.decode(s).map_err(|e| format!("dpop b64: {e}"))
}

fn field<'a>(jwk: &'a serde_json::Value, k: &str) -> Result<&'a str, String> {
    jwk.get(k).and_then(|v| v.as_str()).ok_or_else(|| format!("dpop jwk tanpa `{k}`"))
}

/// JWK thumbprint RFC 7638: hanya member wajib, urut leksikografis.
pub fn thumbprint(jwk: &serde_json::Value) -> Result<String, String> {
    let canon = match field(jwk, "kty")? {
        "RSA" => format!("{{\"e\":\"{}\",\"kty\":\"RSA\",\"n\":\"{}\"}}", field(jwk, "e")?, field(jwk, "n")?),
        "EC" => format!(
            "{{\"crv\":\"{}\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
            field(jwk, "crv")?,
            field(jwk, "x")?,
            field(jwk, "y")?
        ),
        k => return Err(format!("dpop kty `{k}` belum didukung (RSA/EC)")),
    };
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(canon.as_bytes())))
}

/// Hash access token untuk klaim `ath`.
pub fn ath(access_token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes()))
}

fn algorithm(alg: &str, kty: &str) -> Result<jsonwebtoken::Algorithm, String> {
    match (alg, kty) {
        ("RS256", "RSA") => Ok(jsonwebtoken::Algorithm::RS256),
        ("ES256", "EC") => Ok(jsonwebtoken::Algorithm::ES256),
        ("ES384", "EC") => Ok(jsonwebtoken::Algorithm::ES384),
        _ => Err(format!("dpop kombinasi alg `{alg}` + kty `{kty}` ditolak")),
    }
}

fn decoding_key(jwk: &serde_json::Value) -> Result<jsonwebtoken::DecodingKey, String> {
    match field(jwk, "kty")? {
        "RSA" => jsonwebtoken::DecodingKey::from_rsa_components(field(jwk, "n")?, field(jwk, "e")?)
            .map_err(|e| format!("dpop kunci RSA: {e}")),
        "EC" => jsonwebtoken::DecodingKey::from_ec_components(field(jwk, "x")?, field(jwk, "y")?)
            .map_err(|e| format!("dpop kunci EC: {e}")),
        k => Err(format!("dpop kty `{k}` belum didukung (RSA/EC)")),
    }
}

/// Samakan representasi htu: buang query/fragment + port default implisit.
pub fn normalize_htu(htu: &str) -> String {
    let bare = htu.split(['?', '#']).next().unwrap_or(htu);
    if let Some(rest) = bare.strip_prefix("http://") {
        if let Some(stripped) = rest.strip_suffix(":80") {
            return format!("http://{stripped}");
        }
        if let Some((host, path)) = rest.split_once('/') {
            if let Some(h) = host.strip_suffix(":80") {
                return format!("http://{h}/{path}");
            }
        }
    }
    if let Some(rest) = bare.strip_prefix("https://") {
        if let Some((host, path)) = rest.split_once('/') {
            if let Some(h) = host.strip_suffix(":443") {
                return format!("https://{h}/{path}");
            }
        }
    }
    bare.to_string()
}

pub struct VerifiedProof {
    pub jkt: String,
    pub jti: String,
}

/// Bukti DPoP yang dibawa request penerbitan (login/refresh).
pub struct DpopRequest<'a> {
    pub proof: &'a str,
    pub method: &'a str,
    pub uri: &'a str,
}

/// Verifikasi proof DPoP untuk satu request. `access_token` = Some saat akses
/// resource (wajib cek `ath`); None saat penerbitan (login/refresh, belum ada token).
pub fn verify_proof(
    proof: &str,
    method: &str,
    expected_htu: &str,
    access_token: Option<&str>,
) -> Result<VerifiedProof, String> {
    let mut parts = proof.split('.');
    let h = parts.next().ok_or("dpop malformat")?;
    let _p = parts.next().ok_or("dpop malformat")?; // payload dibaca via jsonwebtoken::decode
    if parts.next().is_none() || parts.next().is_some() {
        return Err("dpop malformat".into());
    }
    let header: ProofHeader =
        serde_json::from_slice(&b64d(h)?).map_err(|_| "dpop header bukan JSON".to_string())?;
    if header.typ.as_deref() != Some("dpop+jwt") {
        return Err("dpop typ wajib dpop+jwt".into());
    }
    if header.kid.is_some() {
        return Err("dpop dilarang memakai kid (RFC 9449 §4.2)".into());
    }
    let kty = field(&header.jwk, "kty")?;
    let alg = algorithm(&header.alg, kty)?;
    let key = decoding_key(&header.jwk)?;
    let mut validation = jsonwebtoken::Validation::new(alg);
    validation.required_spec_claims.clear(); // proof tak punya exp (hanya iat)
    validation.validate_exp = false;
    let data: jsonwebtoken::TokenData<ProofClaims> =
        jsonwebtoken::decode(proof, &key, &validation).map_err(|e| format!("dpop signature: {e}"))?;
    let c = data.claims;
    if c.htm.to_uppercase() != method.to_uppercase() {
        return Err("dpop htm tak cocok".into());
    }
    if normalize_htu(&c.htu) != normalize_htu(expected_htu) {
        return Err("dpop htu tak cocok".into());
    }
    let now = super::now_secs();
    if c.iat > now.saturating_add(IAT_FUTURE_SECS) || c.iat.saturating_add(IAT_PAST_SECS) < now {
        return Err("dpop iat kedaluwarsa".into());
    }
    if let Some(tok) = access_token {
        match &c.ath {
            Some(a) if a == &ath(tok) => {}
            _ => return Err("dpop ath tak cocok".into()),
        }
    }
    Ok(VerifiedProof {
        jkt: thumbprint(&header.jwk)?,
        jti: c.jti,
    })
}

/// Cache jti anti-replay (TTL pendek, kapasitas dibatasi, fail-closed saat penuh).
#[derive(Default)]
pub struct ReplayCache {
    seen: HashMap<String, Instant>,
}

impl ReplayCache {
    pub fn check(&mut self, jti: &str) -> Result<(), String> {
        let now = Instant::now();
        self.seen.retain(|_, t| *t > now);
        if self.seen.len() >= REPLAY_CAP {
            return Err("dpop replay cache penuh".into());
        }
        if self.seen.insert(jti.to_string(), now + REPLAY_TTL).is_some() {
            return Err("dpop jti dipakai ulang (replay)".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// n kunci RSA test statis (pasangan yang sama di ub-auth-firebase/oidc).
    pub const TEST_N: &str = "60pf_crDdvNI5mkIHCTXDyUryR5PnVuwTTo9nz42ASH2340351xO4tVnhAYC_-VH4aAtjD_VHqjnuw6Cdw0RoDDWVayfD_5FBiigq8DJNT9UtMxt8YVpkn1_btM_xpYtXhk1_UUTe31__rrcoYW7WWauJHc4NBVwOOl55PJPUQ-qpIr_lp8ke05rkg3SSGB3mb0g4FNjoniFY0hoWeVgb403zcPchuym7DodQjbNYy0DjRzYYJ2bPhA2kCtZ4Re2PZ2FAruPk1nTp6VoLfs9ehMAbtY128KD7xHrINv-TK5OCpt2_rBw5jrOX3kJo-r3jkNxS308Hkh1V8kAo-BKMQ";

    /// Cross-check independen (python json+hashlib+base64) atas kunci test nyata.
    /// Kedua implementasi sepakat → kanonikalisasi hampir pasti tepat.
    #[test]
    fn thumbprint_cocok_implementasi_rujukan() {
        let jwk = serde_json::json!({ "kty": "RSA", "n": TEST_N, "e": "AQAB" });
        assert_eq!(thumbprint(&jwk).unwrap(), "_NfUE4W8utueb7NaKjMto9G_bllGal36xcFMPuMQu2U");
    }

    #[test]
    fn normalize_htu_buang_query_dan_port_default() {
        assert_eq!(normalize_htu("http://h:80/a?x=1#f"), "http://h/a");
        assert_eq!(normalize_htu("https://h:443/a"), "https://h/a");
        assert_eq!(normalize_htu("http://h:8080/a"), "http://h:8080/a");
        assert_eq!(normalize_htu("http://h/a"), "http://h/a");
    }

    #[test]
    fn replay_cache_menolak_pakai_ulang() {
        let mut c = ReplayCache::default();
        assert!(c.check("j1").is_ok());
        assert!(c.check("j1").is_err());
        assert!(c.check("j2").is_ok());
    }
}

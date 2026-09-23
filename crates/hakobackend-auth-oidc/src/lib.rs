//! hakobackend-auth-oidc: verifier-only OIDC generik (Keycloak, Auth0, Google, …).
//!
//! Discovery (`{issuer}/.well-known/openid-configuration` → `jwks_uri`) +
//! verifikasi RS256 via JWKS (cache 1 jam). `iss` wajib cocok; `aud` dicek
//! hanya bila `UB_OIDC_AUDIENCE` diisi. Stateless, tanpa user store.
//! Env: `UB_OIDC_ISSUER` (wajib), `UB_OIDC_AUDIENCE` (opsional),
//! `UB_OIDC_JWKS_URL` (opsional — lewati discovery, untuk test).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use hakobackend_core::{AppError, AuthProvider, Claims};

const CACHE_TTL: Duration = Duration::from_secs(3600);

struct Jwks {
    fetched_at: Option<Instant>,
    keys: HashMap<String, (String, String)>, // kid -> (n, e) base64url
}

pub struct OidcVerifier {
    issuer: String,
    audience: Option<String>,
    jwks_url: Option<String>,
    client: reqwest::Client,
    cache: tokio::sync::RwLock<Jwks>,
}

impl OidcVerifier {
    pub fn from_env() -> Result<Arc<dyn AuthProvider>, String> {
        let issuer = std::env::var("UB_OIDC_ISSUER")
            .map_err(|_| "auth oidc butuh env UB_OIDC_ISSUER".to_string())?;
        let audience = std::env::var("UB_OIDC_AUDIENCE").ok();
        let jwks_url = std::env::var("UB_OIDC_JWKS_URL").ok();
        Ok(Self::with_config(issuer, audience, jwks_url))
    }

    /// Konstruktor eksplisit (dipakai test — tanpa env, hermetis).
    pub fn with_config(issuer: String, audience: Option<String>, jwks_url: Option<String>) -> Arc<dyn AuthProvider> {
        Arc::new(Self {
            issuer,
            audience,
            jwks_url,
            client: reqwest::Client::new(),
            cache: tokio::sync::RwLock::new(Jwks {
                fetched_at: None,
                keys: HashMap::new(),
            }),
        })
    }

    async fn jwks(&self) -> Result<HashMap<String, (String, String)>, AppError> {
        {
            let g = self.cache.read().await;
            if let Some(t) = g.fetched_at {
                if t.elapsed() < CACHE_TTL {
                    return Ok(g.keys.clone());
                }
            }
        }
        let url = match &self.jwks_url {
            Some(u) => u.clone(),
            None => {
                let disc: HashMap<String, serde_json::Value> = self
                    .client
                    .get(format!("{}/.well-known/openid-configuration", self.issuer))
                    .send()
                    .await
                    .map_err(|_| AppError::PermissionDenied)?
                    .json()
                    .await
                    .map_err(|_| AppError::PermissionDenied)?;
                disc.get("jwks_uri")
                    .and_then(|v| v.as_str())
                    .ok_or(AppError::PermissionDenied)?
                    .to_string()
            }
        };
        let doc: HashMap<String, serde_json::Value> = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|_| AppError::PermissionDenied)?
            .json()
            .await
            .map_err(|_| AppError::PermissionDenied)?;
        let mut keys = HashMap::new();
        if let Some(arr) = doc.get("keys").and_then(|v| v.as_array()) {
            for k in arr {
                if let (Some(kid), Some(n), Some(e)) = (
                    k.get("kid").and_then(|v| v.as_str()),
                    k.get("n").and_then(|v| v.as_str()),
                    k.get("e").and_then(|v| v.as_str()),
                ) {
                    keys.insert(kid.to_string(), (n.to_string(), e.to_string()));
                }
            }
        }
        *self.cache.write().await = Jwks {
            fetched_at: Some(Instant::now()),
            keys: keys.clone(),
        };
        Ok(keys)
    }
}

#[async_trait::async_trait]
impl AuthProvider for OidcVerifier {
    fn name(&self) -> &'static str {
        "oidc"
    }

    async fn verify(&self, token: &str) -> Result<Claims, AppError> {
        let kid = jsonwebtoken::decode_header(token)
            .map_err(|_| AppError::PermissionDenied)?
            .kid
            .ok_or(AppError::PermissionDenied)?;
        let (n, e) = self.jwks().await?.get(&kid).cloned().ok_or(AppError::PermissionDenied)?;
        let key = jsonwebtoken::DecodingKey::from_rsa_components(&n, &e)
            .map_err(|_| AppError::PermissionDenied)?;
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_issuer(&[self.issuer.as_str()]);
        if let Some(aud) = &self.audience {
            validation.set_audience(&[aud.as_str()]);
        }
        let data: jsonwebtoken::TokenData<HashMap<String, serde_json::Value>> =
            jsonwebtoken::decode(token, &key, &validation).map_err(|_| AppError::PermissionDenied)?;
        let sub = data
            .claims
            .get("sub")
            .and_then(|v| v.as_str())
            .ok_or(AppError::PermissionDenied)?
            .to_string();
        let email = data.claims.get("email").and_then(|v| v.as_str()).map(str::to_string);
        Ok(Claims {
            provider: "oidc",
            uid: sub,
            email,
            extra: data.claims,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Kunci test statis (pasangan yang sama dengan hakobackend-auth-firebase).
    const TEST_PRIV_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDrSl/9ysN280jm\naQgcJNcPJSvJHk+dW7BNOj2fPjYBIfbfjTfnXE7i1WeEBgL/5UfhoC2MP9UeqOe7\nDoJ3DRGgMNZVrJ8P/kUGKKCrwMk1P1S0zG3xhWmSfX9u0z/Gli1eGTX9RRN7fX/+\nutyhhbtZZq4kdzg0FXA46Xnk8k9RD6qkiv+WnyR7TmuSDdJIYHeZvSDgU2OieIVj\nSGhZ5WBvjTfNw9yG7KbsOh1CNs1jLQONHNhgnZs+EDaQK1nhF7Y9nYUCu4+TWdOn\npWgt+z16EwBu1jXbwoPvEesg2/5Mrk4Km3b+sHDmOs5feQmj6veOQ3FLfTweSHVX\nyQCj4EoxAgMBAAECggEAff9zDf5B0/YN6Mz/+cpEnCiknOutaK/L5l801ozC8LJW\neHowIKYO3Gu5Jjrt6kjGyG01VvBr2SJMDaCEfuoxsR3V+UUaXL8mCVlCSRdQ6EHE\nw5jhmz99PGQWFKvtcBPFsalAfyM5fpzDKQ65zYlGvWY+BOsO3t1IHkHw84hKrzX0\nfNZS4Ppxug2PylXP9cDsUUcjMmZpTAYeWKcOprMIRMutjnJmf0e+n1ldL+643fHV\nZHuQ0NX9k7Bmm4jcy2eonWStj00Hw5M99u9XdhSjLjO2PDBrwUmbDXeQYJJ9QjfX\naneV3krMJ1+BFXKfN+MsSQMaDEn4QAf6w5oV3j12bQKBgQD+hKdpHluCN9curPw4\n1401n8W8NkrQ6eQmSHYBtW4CcTMHDdtM/xPPFRmELRe3u4l5rVygVfD0PNMW169c\nn/RXqrw6qH7L1qax+WW3f6UZat/KF8soaI55Dn3u6cJdLgdXlCadtREGcX15z2Pm\nRfeWw2iJ64eqOX42zuUXm2Zd2wKBgQDsqRAuWJiybomg37A1Yqrf+xf9Iw1HwJ11\nLfeK0Uztljdzlo5qcqPkphYrlTLchQG8sx+dMQBF+dXEI4rF1haYvVbP78NChoQo\njt2c5w7FCuWncvRSxYpzU5QUyDXWoH5KlnjQhUAS2vPRGhitrI2gRIY4v9DjqFii\nV0gVAHyD4wKBgQCWDcNdeCZfOWjF/fqd0IdSLCY59pBZZuu5nlLkYwC+s9pvuD2o\nwWH+XuQyRxuKmShN8mV/qetrM0kIWJTsuOknnmNm+dv3dU/F8dGEQ98kgxv5W9nM\nswf8WwzoBC0xHmf5vECgDhZBhDuDyz+MjYeQ/Rfu6EuNkmPVEFmEd3v8rQKBgQDH\nxA28kVyTgWr7ONZsudSzLCibrLLRFm3TM/H4Y6QkCODV2QhuIkbmAqxELbS5ICzP\nNARDk9E/QByJa9cAGC8KzwgwjZqs1Q9JjQ7UGtYEzaX9KrPCCq1LnAkrYbTQbrks\nDMf+e/wR7nBQ2U5ri3QhDLafwIp7IOdwYWyfDcINMQKBgB8ZkBiNiMngr59o2Y7/\nTF2sD5CSZmWd0SGhJivzcxlWWUVtZGpXgO0h6cAyTIAQJCNxox5IMNCnbtnVmQzV\nZeS8kwffcMXV7LBYEHgYlJo5gtBzPadXkXtKAQqT9jxZGjAziI7iKjr4U2vIcblm\n8mM8f3Z5FfbC828Q4rYaROLf\n-----END PRIVATE KEY-----\n";
    /// n/e base64url dari kunci di atas (untuk JWKS mock).
    const TEST_N: &str = "60pf_crDdvNI5mkIHCTXDyUryR5PnVuwTTo9nz42ASH2340351xO4tVnhAYC_-VH4aAtjD_VHqjnuw6Cdw0RoDDWVayfD_5FBiigq8DJNT9UtMxt8YVpkn1_btM_xpYtXhk1_UUTe31__rrcoYW7WWauJHc4NBVwOOl55PJPUQ-qpIr_lp8ke05rkg3SSGB3mb0g4FNjoniFY0hoWeVgb403zcPchuym7DodQjbNYy0DjRzYYJ2bPhA2kCtZ4Re2PZ2FAruPk1nTp6VoLfs9ehMAbtY128KD7xHrINv-TK5OCpt2_rBw5jrOX3kJo-r3jkNxS308Hkh1V8kAo-BKMQ";
    const TEST_E: &str = "AQAB";

    /// Mock OIDC: discovery + JWKS statis.
    /// Framing HTTP benar (bukan single-read) + soket blocking — lihat hakobackend-auth-github.
    fn mock_oidc() -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let b2 = base.clone();
        let handle = std::thread::spawn(move || {
            let mut idle = 0;
            while idle < 8 {
                match listener.accept() {
                    Ok((mut s, _)) => {
                        idle = 0;
                        let _ = s.set_nonblocking(false);
                        let mut raw = Vec::new();
                        let mut buf = [0u8; 4096];
                        loop {
                            match s.read(&mut buf) {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    raw.extend_from_slice(&buf[..n]);
                                    if raw.windows(4).any(|w| w == b"\r\n\r\n") {
                                        break;
                                    }
                                    if raw.len() > 65536 {
                                        break;
                                    }
                                }
                            }
                        }
                        let req: String = String::from_utf8_lossy(&raw).into_owned();
                        let body = if req.contains("openid-configuration") {
                            serde_json::json!({"issuer": b2, "jwks_uri": format!("{b2}/jwks")}).to_string()
                        } else {
                            serde_json::json!({"keys": [{"kty": "RSA", "kid": "k1", "n": TEST_N, "e": TEST_E}]}).to_string()
                        };
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = s.write_all(resp.as_bytes());
                    }
                    Err(_) => {
                        idle += 1;
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }
                }
            }
        });
        (base, handle)
    }

    #[tokio::test]
    async fn verify_discovery_jwks_posisi() {
        let (base, server) = mock_oidc();

        // Konstruktor eksplisit — tanpa env, hermetis antar-test paralel.
        let v = OidcVerifier::with_config(base.clone(), Some("klien-saya".into()), None);

        let enc = jsonwebtoken::EncodingKey::from_rsa_pem(TEST_PRIV_PEM.as_bytes()).unwrap();
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some("k1".into());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;
        let token = jsonwebtoken::encode(
            &header,
            &serde_json::json!({"sub": "user-7", "aud": "klien-saya", "iss": base.clone(), "exp": now + 3600}),
            &enc,
        )
        .unwrap();
        let c = v.verify(&token).await.unwrap();
        assert_eq!((c.provider, c.uid.as_str()), ("oidc", "user-7"));

        // Aud salah → tolak.
        let bad = jsonwebtoken::encode(
            &header,
            &serde_json::json!({"sub": "user-7", "aud": "orang-lain", "iss": base, "exp": now + 3600}),
            &enc,
        )
        .unwrap();
        assert!(v.verify(&bad).await.is_err());
        assert!(v.verify("rusak").await.is_err());
        server.join().unwrap();
    }

    #[test]
    fn from_env_butuh_issuer() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("UB_OIDC_ISSUER");
        assert!(OidcVerifier::from_env().is_err());
    }
}

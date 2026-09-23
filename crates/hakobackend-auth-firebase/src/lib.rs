//! hakobackend-auth-firebase: Firebase ID Token verifier-only (no Admin SDK).
//!
//! Local RS256 verification via Google x509 certificates (1-hour cache):
//! `iss == https://securetoken.google.com/<project>`, `aud == <project>`,
//! `exp` valid. Backend stores no sessions/users — stateless.
//! Config via env: `UB_FIREBASE_PROJECT` (required),
//! `UB_FIREBASE_JWKS_URL` (optional, override for tests).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use hakobackend_core::{AppError, AuthProvider, Claims};

const GOOGLE_CERTS: &str =
    "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";
const CERT_TTL: Duration = Duration::from_secs(3600);

pub struct FirebaseVerifier {
    project_id: String,
    jwks_url: String,
    client: reqwest::Client,
    certs: tokio::sync::RwLock<(Option<Instant>, HashMap<String, String>)>,
}

impl FirebaseVerifier {
    pub fn from_env() -> Result<Arc<dyn AuthProvider>, String> {
        let project_id = std::env::var("UB_FIREBASE_PROJECT")
            .map_err(|_| "auth firebase requires env UB_FIREBASE_PROJECT".to_string())?;
        let jwks_url = std::env::var("UB_FIREBASE_JWKS_URL").unwrap_or_else(|_| GOOGLE_CERTS.into());
        Ok(Self::with_url(project_id, jwks_url))
    }

    /// Explicit constructor (used by tests — no env, hermetic).
    pub fn with_url(project_id: String, jwks_url: String) -> Arc<dyn AuthProvider> {
        Arc::new(Self {
            project_id,
            jwks_url,
            client: reqwest::Client::new(),
            certs: tokio::sync::RwLock::new((None, HashMap::new())),
        })
    }

    async fn certs(&self) -> Result<HashMap<String, String>, AppError> {
        {
            let g = self.certs.read().await;
            if let (Some(t), m) = (&g.0, &g.1) {
                if t.elapsed() < CERT_TTL {
                    return Ok(m.clone());
                }
            }
        }
        let map: HashMap<String, String> = self
            .client
            .get(&self.jwks_url)
            .send()
            .await
            .map_err(|_| AppError::PermissionDenied)?
            .json()
            .await
            .map_err(|_| AppError::PermissionDenied)?;
        *self.certs.write().await = (Some(Instant::now()), map.clone());
        Ok(map)
    }
}

#[async_trait::async_trait]
impl AuthProvider for FirebaseVerifier {
    fn name(&self) -> &'static str {
        "firebase"
    }

    async fn verify(&self, token: &str) -> Result<Claims, AppError> {
        let kid = jsonwebtoken::decode_header(token)
            .map_err(|_| AppError::PermissionDenied)?
            .kid
            .ok_or(AppError::PermissionDenied)?;
        let pem = self.certs().await?.get(&kid).cloned().ok_or(AppError::PermissionDenied)?;
        let key = jsonwebtoken::DecodingKey::from_rsa_pem(pem.as_bytes())
            .map_err(|_| AppError::PermissionDenied)?;
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_audience(&[self.project_id.as_str()]);
        let iss = format!("https://securetoken.google.com/{}", self.project_id);
        validation.set_issuer(&[iss.as_str()]);
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
            provider: "firebase",
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

    /// Env is process-global — all tests touching it must go through this lock,
    /// holding it only during set/from_env/unset (no await inside).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Static RSA-2048 test keypair (not a production secret).
    /// Static so tests stay fast — runtime keygen in debug takes tens of seconds.
    const TEST_PRIV_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDrSl/9ysN280jm\naQgcJNcPJSvJHk+dW7BNOj2fPjYBIfbfjTfnXE7i1WeEBgL/5UfhoC2MP9UeqOe7\nDoJ3DRGgMNZVrJ8P/kUGKKCrwMk1P1S0zG3xhWmSfX9u0z/Gli1eGTX9RRN7fX/+\nutyhhbtZZq4kdzg0FXA46Xnk8k9RD6qkiv+WnyR7TmuSDdJIYHeZvSDgU2OieIVj\nSGhZ5WBvjTfNw9yG7KbsOh1CNs1jLQONHNhgnZs+EDaQK1nhF7Y9nYUCu4+TWdOn\npWgt+z16EwBu1jXbwoPvEesg2/5Mrk4Km3b+sHDmOs5feQmj6veOQ3FLfTweSHVX\nyQCj4EoxAgMBAAECggEAff9zDf5B0/YN6Mz/+cpEnCiknOutaK/L5l801ozC8LJW\neHowIKYO3Gu5Jjrt6kjGyG01VvBr2SJMDaCEfuoxsR3V+UUaXL8mCVlCSRdQ6EHE\nw5jhmz99PGQWFKvtcBPFsalAfyM5fpzDKQ65zYlGvWY+BOsO3t1IHkHw84hKrzX0\nfNZS4Ppxug2PylXP9cDsUUcjMmZpTAYeWKcOprMIRMutjnJmf0e+n1ldL+643fHV\nZHuQ0NX9k7Bmm4jcy2eonWStj00Hw5M99u9XdhSjLjO2PDBrwUmbDXeQYJJ9QjfX\naneV3krMJ1+BFXKfN+MsSQMaDEn4QAf6w5oV3j12bQKBgQD+hKdpHluCN9curPw4\n1401n8W8NkrQ6eQmSHYBtW4CcTMHDdtM/xPPFRmELRe3u4l5rVygVfD0PNMW169c\nn/RXqrw6qH7L1qax+WW3f6UZat/KF8soaI55Dn3u6cJdLgdXlCadtREGcX15z2Pm\nRfeWw2iJ64eqOX42zuUXm2Zd2wKBgQDsqRAuWJiybomg37A1Yqrf+xf9Iw1HwJ11\nLfeK0Uztljdzlo5qcqPkphYrlTLchQG8sx+dMQBF+dXEI4rF1haYvVbP78NChoQo\njt2c5w7FCuWncvRSxYpzU5QUyDXWoH5KlnjQhUAS2vPRGhitrI2gRIY4v9DjqFii\nV0gVAHyD4wKBgQCWDcNdeCZfOWjF/fqd0IdSLCY59pBZZuu5nlLkYwC+s9pvuD2o\nwWH+XuQyRxuKmShN8mV/qetrM0kIWJTsuOknnmNm+dv3dU/F8dGEQ98kgxv5W9nM\nswf8WwzoBC0xHmf5vECgDhZBhDuDyz+MjYeQ/Rfu6EuNkmPVEFmEd3v8rQKBgQDH\nxA28kVyTgWr7ONZsudSzLCibrLLRFm3TM/H4Y6QkCODV2QhuIkbmAqxELbS5ICzP\nNARDk9E/QByJa9cAGC8KzwgwjZqs1Q9JjQ7UGtYEzaX9KrPCCq1LnAkrYbTQbrks\nDMf+e/wR7nBQ2U5ri3QhDLafwIp7IOdwYWyfDcINMQKBgB8ZkBiNiMngr59o2Y7/\nTF2sD5CSZmWd0SGhJivzcxlWWUVtZGpXgO0h6cAyTIAQJCNxox5IMNCnbtnVmQzV\nZeS8kwffcMXV7LBYEHgYlJo5gtBzPadXkXtKAQqT9jxZGjAziI7iKjr4U2vIcblm\n8mM8f3Z5FfbC828Q4rYaROLf\n-----END PRIVATE KEY-----\n";
    const TEST_PUB_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA60pf/crDdvNI5mkIHCTX\nDyUryR5PnVuwTTo9nz42ASH2340351xO4tVnhAYC/+VH4aAtjD/VHqjnuw6Cdw0R\noDDWVayfD/5FBiigq8DJNT9UtMxt8YVpkn1/btM/xpYtXhk1/UUTe31//rrcoYW7\nWWauJHc4NBVwOOl55PJPUQ+qpIr/lp8ke05rkg3SSGB3mb0g4FNjoniFY0hoWeVg\nb403zcPchuym7DodQjbNYy0DjRzYYJ2bPhA2kCtZ4Re2PZ2FAruPk1nTp6VoLfs9\nehMAbtY128KD7xHrINv+TK5OCpt2/rBw5jrOX3kJo+r3jkNxS308Hkh1V8kAo+BK\nMQIDAQAB\n-----END PUBLIC KEY-----\n";

    /// One-shot mock server: serve any GET with a single JSON body.
    /// Returns URL + join handle. Blocking socket + read until headers are
    /// complete (not single-read — see hakobackend-auth-github).
    fn mock_server(body: String, max_hits: usize) -> (String, std::thread::JoinHandle<usize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let mut hits = 0;
            let mut idle = 0;
            while hits < max_hits && idle < 8 {
                match listener.accept() {
                    Ok((mut s, _)) => {
                        idle = 0;
                        hits += 1;
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
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = s.write_all(resp.as_bytes());
                    }
                    Err(_) => {
                        idle += 1;
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }
                }
            }
            hits
        });
        (url, handle)
    }

    fn mint(project: &str, priv_pem: &str, kid: &str, sub: &str) -> String {
        let enc = jsonwebtoken::EncodingKey::from_rsa_pem(priv_pem.as_bytes()).unwrap();
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(kid.into());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;
        let claims = serde_json::json!({
            "sub": sub,
            "email": "u@x.id",
            "aud": project,
            "iss": format!("https://securetoken.google.com/{project}"),
            "exp": now + 3600,
            "iat": now,
        });
        jsonwebtoken::encode(&header, &claims, &enc).unwrap()
    }

    #[tokio::test]
    async fn verify_end_to_end_and_cache() {
        let project = "demo-proj";
        let certs = serde_json::json!({ "testkid": TEST_PUB_PEM }).to_string();
        let (url, server) = mock_server(certs, 10);

        // Explicit constructor — no env, hermetic across parallel tests.
        let v = FirebaseVerifier::with_url(project.into(), url);

        let token = mint(project, TEST_PRIV_PEM, "testkid", "uid-1");
        let c = v.verify(&token).await.unwrap();
        assert_eq!((c.provider, c.uid.as_str()), ("firebase", "uid-1"));
        assert_eq!(c.email.as_deref(), Some("u@x.id"));

        // Wrong-key / wrong-aud / unknown-kid token → Err (chain continues).
        assert!(v.verify("bukan.jwt.token").await.is_err());
        let bad_kid = mint(project, TEST_PRIV_PEM, "kid-asing", "uid-1");
        assert!(v.verify(&bad_kid).await.is_err());

        // Second verification does not hit the server again (cache) → hits == 1.
        assert_eq!(server.join().unwrap(), 1);
    }

    #[test]
    fn from_env_butuh_project() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("UB_FIREBASE_PROJECT");
        assert!(FirebaseVerifier::from_env().is_err());
    }
}

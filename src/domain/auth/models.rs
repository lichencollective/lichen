use serde::{Deserialize, Serialize};
use std::time::SystemTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub id_token: String,
    pub access_token_expires_at: SystemTime,
    pub refresh_token_expires_at: SystemTime,
}

impl SessionTokens {
    pub fn access_token_expired(&self) -> bool {
        self.access_token_expires_at < SystemTime::now()
    }

    pub fn refresh_token_expired(&self) -> bool {
        self.refresh_token_expires_at < SystemTime::now()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    fn session_token_unexpired() -> SessionTokens {
        SessionTokens {
            access_token: "".to_string(),
            refresh_token: "".to_string(),
            id_token: "".to_string(),
            access_token_expires_at: SystemTime::now()
                .checked_add(Duration::from_mins(5))
                .unwrap(),
            refresh_token_expires_at: SystemTime::now()
                .checked_add(Duration::from_mins(5))
                .unwrap(),
        }
    }

    fn session_token_expired() -> SessionTokens {
        SessionTokens {
            access_token: "".to_string(),
            refresh_token: "".to_string(),
            id_token: "".to_string(),
            access_token_expires_at: SystemTime::UNIX_EPOCH,
            refresh_token_expires_at: SystemTime::UNIX_EPOCH,
        }
    }

    #[tokio::test]
    async fn test_refresh_token_expired_unexpired() {
        let session_token = session_token_unexpired();

        assert_eq!(false, session_token.refresh_token_expired());
    }

    #[tokio::test]
    async fn test_refresh_token_expired_expired() {
        let session_token = session_token_expired();

        assert_eq!(true, session_token.refresh_token_expired());
    }

    #[tokio::test]
    async fn test_access_token_expired_unexpired() {
        let session_token = session_token_unexpired();

        assert_eq!(false, session_token.access_token_expired());
    }

    #[tokio::test]
    async fn test_access_token_expired_expired() {
        let session_token = session_token_expired();

        assert_eq!(true, session_token.access_token_expired());
    }
}

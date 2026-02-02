use crate::domain::auth::SessionTokens;
use async_trait::async_trait;
use mockall::automock;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("error writing session")]
    WriteSessionError,

    #[error("error reading session")]
    ReadSessionError,
    #[error(transparent)]
    TowerSessionsError(#[from] tower_sessions::session::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionLoginCallback {
    pub app_uri: String,
    pub nonce: String,
    pub csrf_token: String,
    pub pkce_verifier: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSession {
    pub session_tokens: SessionTokens,
    pub user_id: String,
    pub groups: Vec<String>,
    pub username: Option<String>,
}

#[async_trait]
#[automock]
pub trait SessionPort: Send + Sync {
    async fn write_oidc_callback(&self, params: SessionLoginCallback) -> Result<(), SessionError>;
    async fn get_oidc_callback(&self) -> Result<Option<SessionLoginCallback>, SessionError>;
    async fn write_user_session(&self, params: UserSession) -> Result<(), SessionError>;
    async fn get_user_session(&self) -> Result<Option<UserSession>, SessionError>;
    async fn flush(&self) -> Result<(), SessionError>;
}

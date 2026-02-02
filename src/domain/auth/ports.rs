use crate::domain::auth::SessionTokens;
use async_trait::async_trait;
use mockall::automock;
use openidconnect::url;
use thiserror::Error;
use tower_sessions::Session;

////////////////////////////////////////////////////////////////////////////////////////////////////
// Service
////////////////////////////////////////////////////////////////////////////////////////////////////

#[async_trait]
#[cfg_attr(test, mockall::automock)]
pub trait AuthService: Send + Sync {
    async fn login(
        &self,
        params: ServiceLoginParams,
    ) -> Result<ServiceLoginResult, ServiceLoginError>;
    async fn callback(
        &self,
        params: ServiceCallbackParams,
    ) -> Result<ServiceCallbackResult, ServiceCallbackError>;
    async fn logout(&self, params: ServiceLogoutParams) -> Result<(), ServiceLogoutError>;
    async fn authenticated(
        &self,
        params: ServiceAuthenticatedParams,
    ) -> Result<bool, ServiceAuthenticatedError>;
    async fn profile(
        &self,
        params: ServiceProfileParams,
    ) -> Result<ServiceProfileResult, ServiceProfileError>;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Ports
////////////////////////////////////////////////////////////////////////////////////////////////////

#[async_trait]
#[automock]
pub trait OIDCPort: Send + Sync {
    async fn login(&self, params: OIDCLoginParams) -> OIDCLoginResult;
    async fn callback(
        &self,
        params: OIDCCallbackParams,
    ) -> Result<OIDCCallbackResult, OIDCCallbackError>;
    async fn refresh(
        &self,
        params: OIDCRefreshParams,
    ) -> Result<OIDCRefreshResult, OIDCRefreshError>;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Results
////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct ServiceLoginResult {
    pub authorization_uri: String,
}

pub struct ServiceCallbackResult {
    pub redirect_uri: String,
}

pub struct ServiceProfileResult {
    pub user_id: String,
    pub groups: Vec<String>,
    pub username: Option<String>,
}

pub struct OIDCLoginResult {
    pub authorization_url: String,
    pub csrf_token: String,
    pub nonce: String,
    pub pkce_verifier: String,
}

pub struct OIDCCallbackResult {
    pub session_tokens: SessionTokens,
    pub subject: String,
    pub groups: Vec<String>,
    pub username: Option<String>,
}

pub struct OIDCLogoutResult {}

pub struct OIDCRefreshResult {
    pub session_tokens: SessionTokens,
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Params
////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct ServiceLoginParams {
    pub session: Session,
    pub app_uri: String,
}

pub struct ServiceCallbackParams {
    pub session: Session,
    pub state: String,
    pub code: String,
}

pub struct ServiceLogoutParams {
    pub session: Session,
    pub app_uri: String,
}

pub struct ServiceAuthenticatedParams {
    pub session: Session,
}

pub struct ServiceProfileParams {
    pub session: Session,
}

pub struct OIDCLoginParams {}

pub struct OIDCCallbackParams {
    pub code: String,
    pub pkce_code_verifier: String,
    pub nonce: String,
}

pub struct OIDCRefreshParams {
    pub subject: String,
    pub refresh_token: String,
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Errors
////////////////////////////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Error)]
pub enum ServiceLoginError {
    #[error(transparent)]
    SessionError(#[from] crate::domain::session::SessionError),
}

#[derive(Debug, Error)]
pub enum ServiceCallbackError {
    #[error("invalid session")]
    InvalidSession,

    #[error(transparent)]
    SessionError(#[from] crate::domain::session::SessionError),

    #[error(transparent)]
    OIDCError(#[from] OIDCCallbackError),
}

#[derive(Debug, Error)]
pub enum ServiceLogoutError {
    #[error(transparent)]
    SessionError(#[from] crate::domain::session::SessionError),
}

#[derive(Debug, Error)]
pub enum ServiceAuthenticatedError {
    #[error(transparent)]
    SessionError(#[from] crate::domain::session::SessionError),

    #[error(transparent)]
    OIDCRefreshError(#[from] OIDCRefreshError),
}

#[derive(Debug, Error)]
pub enum ServiceProfileError {
    #[error("user is not authenticated")]
    Unauthenticated,

    #[error(transparent)]
    SessionError(#[from] crate::domain::session::SessionError),
}

#[derive(Debug, Error)]
pub enum OIDCLoginError {
    #[error(transparent)]
    URLParseError(#[from] url::ParseError),
}

#[derive(Debug, Error)]
pub enum OIDCCallbackError {
    #[error(transparent)]
    RegexError(#[from] regex::Error),

    #[error("token exchange failed")]
    RequestTokenError,

    #[error(transparent)]
    ConfigurationError(#[from] oauth2::ConfigurationError),

    #[error("token decode error")]
    TokenDecodeError,

    #[error("there was no id token")]
    NoIDTokenError,

    #[error(transparent)]
    ClaimsError(#[from] openidconnect::ClaimsVerificationError),

    #[error("failed to get user info")]
    UserInfoError,
}

#[derive(Debug, Error)]
pub enum OIDCRefreshError {
    #[error("token exchange failed")]
    RefreshTokenError,

    #[error("token decode error")]
    TokenDecodeError,

    #[error(transparent)]
    ConfigurationError(#[from] oauth2::ConfigurationError),
}

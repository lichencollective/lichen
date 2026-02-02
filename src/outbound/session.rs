use crate::domain::session::{SessionError, SessionLoginCallback, SessionPort, UserSession};
use async_trait::async_trait;
use mockall::automock;
use tower_sessions::Session;

const SESSION_LOGIN_CALLBACK: &str = "login_callback";
const SESSION: &str = "session";

#[automock]
pub trait SessionFactory<S: SessionPort> {
    fn build(&self, session: Session) -> S;
}

#[derive(Debug, Clone)]
pub struct SessionAdapterFactory {}

#[derive(Debug, Clone)]
pub struct SessionAdapter {
    session: Session,
}

impl Default for SessionAdapterFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionAdapterFactory {
    pub fn new() -> Self {
        Self {}
    }
}

impl SessionFactory<SessionAdapter> for SessionAdapterFactory {
    fn build(&self, session: Session) -> SessionAdapter {
        SessionAdapter::new(session)
    }
}

impl SessionAdapter {
    fn new(session: Session) -> Self {
        Self { session }
    }
}

#[async_trait]
impl SessionPort for SessionAdapter {
    async fn write_oidc_callback(&self, params: SessionLoginCallback) -> Result<(), SessionError> {
        self.session.insert(SESSION_LOGIN_CALLBACK, params).await?;

        Ok(())
    }

    async fn get_oidc_callback(&self) -> Result<Option<SessionLoginCallback>, SessionError> {
        let session = self
            .session
            .get::<SessionLoginCallback>(SESSION_LOGIN_CALLBACK)
            .await?;

        Ok(session)
    }

    async fn write_user_session(&self, params: UserSession) -> Result<(), SessionError> {
        self.session.insert(SESSION, params).await?;

        Ok(())
    }

    async fn get_user_session(&self) -> Result<Option<UserSession>, SessionError> {
        let session = self.session.get::<UserSession>(SESSION).await?;

        Ok(session)
    }

    async fn flush(&self) -> Result<(), SessionError> {
        self.session.flush().await?;
        self.session.save().await?;

        Ok(())
    }
}

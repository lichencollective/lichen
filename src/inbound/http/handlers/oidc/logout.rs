use crate::core::application::ApplicationServices;
use crate::domain::auth::{AuthService, ServiceLogoutError, ServiceLogoutParams};
use crate::errors::{AppError, bad_request_invalid_session};
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Redirect};
use serde::Deserialize;
use tower_sessions::Session;

#[derive(Debug, Deserialize)]
pub(crate) struct LogoutQueryParams {
    #[serde(rename = "app_uri")]
    app_uri: String,
}
pub async fn oidc_logout<S: ApplicationServices>(
    State(state): State<S>,
    session: Session,
    logout_query_params: Query<LogoutQueryParams>,
) -> Result<impl IntoResponse, AppError> {
    let auth_service = state.auth_service();

    auth_service
        .logout(ServiceLogoutParams {
            session,
            app_uri: logout_query_params.app_uri.clone(),
        })
        .await
        .map_err(|e| match e {
            ServiceLogoutError::SessionError(_) => bad_request_invalid_session(),
        })?;

    Ok(Redirect::to(logout_query_params.app_uri.as_str()))
}

#[cfg(test)]
mod tests {
    use crate::core::application::Application;
    use crate::core::application::tests::MockAppInstanceParameters;
    use crate::domain::auth::{MockAuthService, ServiceLogoutError};
    use crate::domain::session::SessionError;
    use crate::inbound::http::router;
    use axum_test::TestServer;
    use http::StatusCode;
    use std::future;
    use tower_sessions::MemoryStore;

    #[tokio::test]
    async fn test_oidc_logout() {
        let mut auth_service = MockAuthService::new();
        auth_service
            .expect_logout()
            .times(1)
            .returning(|_| Box::pin(future::ready(Ok(()))));

        let app = Application::<MockAuthService>::mock_instance(MockAppInstanceParameters {
            config: None,
            auth_service: Some(auth_service),
        });
        let session_store = MemoryStore::default();
        let router = router(app, session_store);
        let server = TestServer::new(router).unwrap();

        let response = server
            .get("/backend/oidc/logout?app_uri=https://suse.com")
            .await;

        response.assert_status(StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn test_oidc_logout_error() {
        let mut auth_service = MockAuthService::new();
        auth_service.expect_logout().times(1).returning(|_| {
            Box::pin(future::ready(Err(ServiceLogoutError::SessionError(
                SessionError::ReadSessionError,
            ))))
        });

        let app = Application::<MockAuthService>::mock_instance(MockAppInstanceParameters {
            config: None,
            auth_service: Some(auth_service),
        });
        let session_store = MemoryStore::default();
        let router = router(app, session_store);
        let server = TestServer::new(router).unwrap();

        let response = server
            .get("/backend/oidc/logout?app_uri=https://suse.com")
            .await;

        response.assert_status_bad_request();
    }
}

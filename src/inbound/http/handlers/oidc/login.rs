use crate::core::application::ApplicationServices;
use crate::domain::auth::{AuthService, ServiceLoginError, ServiceLoginParams};
use crate::errors::{AppError, bad_request, bad_request_invalid_session};
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Redirect};
use serde::Deserialize;
use tower_sessions::Session;

#[derive(Debug, Deserialize)]
pub(crate) struct LoginQueryParams {
    #[serde(rename = "app_uri")]
    app_uri: String,
}

pub async fn oidc_login<S: ApplicationServices>(
    State(state): State<S>,
    session: Session,
    login_query_params: Query<LoginQueryParams>,
) -> Result<impl IntoResponse, AppError> {
    let auth_service = state.auth_service();

    if !state
        .config()
        .oidc
        .authorized_callback_urls
        .contains(&login_query_params.app_uri)
    {
        return Err(bad_request());
    }

    let result = auth_service
        .login(ServiceLoginParams {
            session,
            app_uri: login_query_params.app_uri.clone(),
        })
        .await
        .map_err(|e| match e {
            ServiceLoginError::SessionError(_) => bad_request_invalid_session(),
        })?;

    tracing::debug!("login generation successful, redirecting user");
    Ok(Redirect::to(result.authorization_uri.as_str()))
}

#[cfg(test)]
mod tests {
    use crate::core::application::Application;
    use crate::core::application::tests::MockAppInstanceParameters;
    use crate::core::config::{Config, DB, OIDCConfig, RedisConfig};
    use crate::domain::auth::{MockAuthService, ServiceLoginError, ServiceLoginResult};
    use crate::domain::lichen::MockLichenService;
    use crate::domain::session::SessionError;
    use crate::inbound::http::router;
    use axum_test::TestServer;
    use http::StatusCode;
    use std::future;
    use tower_sessions::MemoryStore;

    fn config_with_authorized_callback_urls() -> Config {
        Config {
            cors_hosts: vec![],
            redis: RedisConfig::default(),
            oidc: OIDCConfig {
                url: "".to_string(),
                client_id: "".to_string(),
                client_secret: "".to_string(),
                redirect_url: "".to_string(),
                authorized_callback_urls: vec!["https://suse.com".to_string()],
            },
            db: DB::default(),
            secure_session: false,
        }
    }

    #[tokio::test]
    async fn test_oidc_login() {
        let mut auth_service = MockAuthService::new();
        auth_service.expect_login().times(1).returning(|_| {
            Box::pin(future::ready(Ok(ServiceLoginResult {
                authorization_uri: "".to_string(),
            })))
        });

        let app = Application::<MockAuthService, MockLichenService>::mock_instance(
            MockAppInstanceParameters {
                config: Some(config_with_authorized_callback_urls()),
                auth_service: Some(auth_service),
                lichen_service: None,
            },
        );
        let session_store = MemoryStore::default();
        let router = router(app, session_store);
        let server = TestServer::new(router).unwrap();

        let response = server
            .get("/backend/oidc/login?app_uri=https://suse.com")
            .await;

        response.assert_status(StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn test_oidc_login_no_authorized_callback_urls() {
        let mut auth_service = MockAuthService::new();
        auth_service.expect_login().times(0);

        let app = Application::<MockAuthService, MockLichenService>::mock_instance(
            MockAppInstanceParameters {
                config: None,
                auth_service: Some(auth_service),
                lichen_service: None,
            },
        );
        let session_store = MemoryStore::default();
        let router = router(app, session_store);
        let server = TestServer::new(router).unwrap();

        let response = server
            .get("/backend/oidc/login?app_uri=https://suse.com")
            .await;

        response.assert_status_bad_request();
    }

    #[tokio::test]
    async fn test_oidc_login_session_error() {
        let mut auth_service = MockAuthService::new();
        auth_service.expect_login().times(1).returning(|_| {
            Box::pin(future::ready(Err(ServiceLoginError::SessionError(
                SessionError::ReadSessionError,
            ))))
        });

        let app = Application::<MockAuthService, MockLichenService>::mock_instance(
            MockAppInstanceParameters {
                config: Some(config_with_authorized_callback_urls()),
                auth_service: Some(auth_service),
                lichen_service: None,
            },
        );
        let session_store = MemoryStore::default();
        let router = router(app, session_store);
        let server = TestServer::new(router).unwrap();

        let response = server
            .get("/backend/oidc/login?app_uri=https://suse.com")
            .await;

        response.assert_status_bad_request();
    }
}

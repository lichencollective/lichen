use crate::core::application::ApplicationServices;
use crate::domain::auth::{AuthService, ServiceCallbackError, ServiceCallbackParams};
use crate::errors::{AppError, bad_request, bad_request_invalid_session};
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Redirect};
use serde::Deserialize;
use tower_sessions::Session;

#[derive(Debug, Deserialize)]
pub(crate) struct CallbackQueryParams {
    code: Option<String>,
    state: String,
}

pub async fn oidc_callback<S: ApplicationServices>(
    State(state): State<S>,
    session: Session,
    callback_query_params: Query<CallbackQueryParams>,
) -> Result<impl IntoResponse, AppError> {
    let auth_service = state.auth_service();

    let code = callback_query_params.code.clone().ok_or_else(bad_request)?;

    let result = auth_service
        .callback(ServiceCallbackParams {
            session,
            state: callback_query_params.state.clone(),
            code,
        })
        .await
        .map_err(|e| match e {
            ServiceCallbackError::InvalidSession => bad_request_invalid_session(),
            ServiceCallbackError::SessionError(_) => bad_request_invalid_session(),
            ServiceCallbackError::OIDCError(_) => AppError::InternalServerError,
        })?;

    Ok(Redirect::to(result.redirect_uri.as_str()))
}

#[cfg(test)]
mod tests {
    use crate::core::application::Application;
    use crate::core::application::tests::MockAppInstanceParameters;
    use crate::domain::auth::{
        MockAuthService, OIDCCallbackError, ServiceCallbackError, ServiceCallbackResult,
    };
    use crate::domain::session::SessionError;
    use crate::inbound::http::router;
    use axum_test::TestServer;
    use http::StatusCode;
    use std::future;
    use tower_sessions::MemoryStore;

    #[tokio::test]
    async fn test_oidc_callback() {
        let mut auth_service = MockAuthService::new();
        auth_service.expect_callback().times(1).returning(|_| {
            Box::pin(future::ready(Ok(ServiceCallbackResult {
                redirect_uri: "".to_string(),
            })))
        });

        let app = Application::<MockAuthService>::mock_instance(MockAppInstanceParameters {
            config: None,
            auth_service: Some(auth_service),
        });
        let session_store = MemoryStore::default();
        let router = router(app, session_store);
        let server = TestServer::new(router).unwrap();

        let response = server
            .get("/backend/oidc/callback?state=foo&code=bar")
            .await;

        response.assert_status(StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn test_oidc_invalid_session() {
        let mut auth_service = MockAuthService::new();
        auth_service
            .expect_callback()
            .times(1)
            .returning(|_| Box::pin(future::ready(Err(ServiceCallbackError::InvalidSession))));

        let app = Application::<MockAuthService>::mock_instance(MockAppInstanceParameters {
            config: None,
            auth_service: Some(auth_service),
        });
        let session_store = MemoryStore::default();
        let router = router(app, session_store);
        let server = TestServer::new(router).unwrap();

        let response = server
            .get("/backend/oidc/callback?state=foo&code=bar")
            .await;

        response.assert_status_bad_request();
    }

    #[tokio::test]
    async fn test_oidc_session_error() {
        let mut auth_service = MockAuthService::new();
        auth_service.expect_callback().times(1).returning(|_| {
            Box::pin(future::ready(Err(ServiceCallbackError::SessionError(
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
            .get("/backend/oidc/callback?state=foo&code=bar")
            .await;

        response.assert_status_bad_request();
    }

    #[tokio::test]
    async fn test_oidc_oidc_error() {
        let mut auth_service = MockAuthService::new();
        auth_service.expect_callback().times(1).returning(|_| {
            Box::pin(future::ready(Err(ServiceCallbackError::OIDCError(
                OIDCCallbackError::RequestTokenError,
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
            .get("/backend/oidc/callback?state=foo&code=bar")
            .await;

        response.assert_status_internal_server_error();
    }
}

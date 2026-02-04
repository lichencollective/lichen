use crate::core::application::ApplicationServices;
use crate::domain::auth::{AuthService, ServiceProfileError, ServiceProfileParams};
use crate::errors::{AppError, internal_error};
use axum::extract::State;
use axum::response::IntoResponse;
use tower_sessions::Session;

pub async fn oidc_profile<S: ApplicationServices>(
    State(state): State<S>,
    session: Session,
) -> Result<impl IntoResponse, AppError> {
    let auth_service = state.auth_service();
    let profile = auth_service
        .profile(ServiceProfileParams { session })
        .await
        .map_err(|e| match e {
            ServiceProfileError::Unauthenticated => AppError::Unauthorized(None),
            ServiceProfileError::SessionError(e) => internal_error(e),
        })?;

    Ok(profile)
}

#[cfg(test)]
mod tests {
    use crate::core::application::Application;
    use crate::core::application::tests::MockAppInstanceParameters;
    use crate::domain;
    use crate::domain::auth::{MockAuthService, ServiceProfileError, ServiceProfileResult};
    use crate::domain::lichen::MockLichenService;
    use crate::inbound::http::router;
    use axum_test::TestServer;
    use std::future;
    use tower_sessions::MemoryStore;

    #[tokio::test]
    async fn test_oidc_profile() {
        let mut auth_service = MockAuthService::new();
        auth_service
            .expect_authenticated()
            .times(1)
            .returning(|_| Box::pin(future::ready(Ok(true))));
        auth_service.expect_profile().times(1).returning(|_| {
            Box::pin(future::ready(Ok(ServiceProfileResult {
                user_id: "test".to_string(),
                groups: vec![],
                username: None,
            })))
        });

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

        let response = server.get("/backend/oidc/profile").await;

        response.assert_status_ok();
    }

    #[tokio::test]
    async fn test_oidc_profile_unauthenticated() {
        let mut auth_service = MockAuthService::new();
        auth_service
            .expect_authenticated()
            .times(1)
            .returning(|_| Box::pin(future::ready(Ok(true))));
        auth_service
            .expect_profile()
            .times(1)
            .returning(|_| Box::pin(future::ready(Err(ServiceProfileError::Unauthenticated))));

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

        let response = server.get("/backend/oidc/profile").await;

        response.assert_status_unauthorized();
    }

    #[tokio::test]
    async fn test_oidc_profile_session_error() {
        let mut auth_service = MockAuthService::new();
        auth_service
            .expect_authenticated()
            .times(1)
            .returning(|_| Box::pin(future::ready(Ok(true))));
        auth_service.expect_profile().times(1).returning(|_| {
            Box::pin(future::ready(Err(ServiceProfileError::SessionError(
                domain::session::SessionError::ReadSessionError,
            ))))
        });

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

        let response = server.get("/backend/oidc/profile").await;

        response.assert_status_internal_server_error();
    }
}

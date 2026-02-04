use crate::core::application::ApplicationServices;
use crate::domain::auth::{AuthService, ServiceAuthenticatedError, ServiceAuthenticatedParams};
use crate::errors::AppError;
use axum::extract::{FromRequestParts, Request, State};
use axum::middleware::Next;
use axum::response::Response;
use tower_sessions::Session;

pub async fn auth<S: ApplicationServices>(
    State(state): State<S>,
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let auth_service = state.auth_service();
    let (mut parts, body) = req.into_parts();
    let session = Session::from_request_parts(&mut parts, &state)
        .await
        .map_err(|_e| AppError::InternalServerError)?;

    req = Request::from_parts(parts, body);

    let is_authenticated = auth_service
        .authenticated(ServiceAuthenticatedParams { session })
        .await
        .map_err(|e| match e {
            ServiceAuthenticatedError::SessionError(_) => AppError::Unauthorized(None),
            ServiceAuthenticatedError::OIDCRefreshError(_) => AppError::Unauthorized(None),
        })?;

    if !is_authenticated {
        return Err(AppError::Unauthorized(None));
    }

    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use crate::core::application::Application;
    use crate::core::application::tests::MockAppInstanceParameters;
    use crate::domain::auth::{MockAuthService, OIDCRefreshError, ServiceAuthenticatedError};
    use crate::domain::lichen::MockLichenService;
    use crate::domain::session::SessionError;
    use crate::inbound::http::middleware::auth;
    use axum::Router;
    use axum::middleware::from_fn_with_state;
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum_extra::extract::cookie::SameSite;
    use axum_test::TestServer;
    use http::StatusCode;
    use std::future;
    use time::Duration;
    use tower_sessions::{Expiry, MemoryStore, SessionManagerLayer};

    pub async fn example() -> impl IntoResponse {
        (StatusCode::OK, "")
    }

    #[tokio::test]
    async fn test_oidc_profile() {
        let session_store = MemoryStore::default();
        let session_layer = SessionManagerLayer::new(session_store)
            .with_secure(false)
            .with_expiry(Expiry::OnInactivity(Duration::hours(1)))
            .with_same_site(SameSite::Lax);

        let mut auth_service = MockAuthService::new();
        auth_service
            .expect_authenticated()
            .times(1)
            .returning(|_| Box::pin(future::ready(Ok(true))));

        let app = Application::<MockAuthService, MockLichenService>::mock_instance(
            MockAppInstanceParameters {
                config: None,
                auth_service: Some(auth_service),
                lichen_service: None,
            },
        );

        let router = Router::new()
            .route("/example", get(example))
            .route_layer(from_fn_with_state(
                app,
                auth::<Application<MockAuthService, MockLichenService>>,
            ))
            .layer(session_layer);

        let server = TestServer::new(router).unwrap();

        let response = server.get("/example").await;

        response.assert_status_ok();
    }

    #[tokio::test]
    async fn test_oidc_profile_unauthorized() {
        let session_store = MemoryStore::default();
        let session_layer = SessionManagerLayer::new(session_store)
            .with_secure(false)
            .with_expiry(Expiry::OnInactivity(Duration::hours(1)))
            .with_same_site(SameSite::Lax);

        let mut auth_service = MockAuthService::new();
        auth_service
            .expect_authenticated()
            .times(1)
            .returning(|_| Box::pin(future::ready(Ok(false))));

        let app = Application::<MockAuthService, MockLichenService>::mock_instance(
            MockAppInstanceParameters {
                config: None,
                auth_service: Some(auth_service),
                lichen_service: None,
            },
        );

        let router = Router::new()
            .route("/example", get(example))
            .route_layer(from_fn_with_state(
                app,
                auth::<Application<MockAuthService, MockLichenService>>,
            ))
            .layer(session_layer);

        let server = TestServer::new(router).unwrap();

        let response = server.get("/example").await;

        response.assert_status_unauthorized();
    }

    #[tokio::test]
    async fn test_oidc_session_error() {
        let session_store = MemoryStore::default();
        let session_layer = SessionManagerLayer::new(session_store)
            .with_secure(false)
            .with_expiry(Expiry::OnInactivity(Duration::hours(1)))
            .with_same_site(SameSite::Lax);

        let mut auth_service = MockAuthService::new();
        auth_service.expect_authenticated().times(1).returning(|_| {
            Box::pin(future::ready(Err(ServiceAuthenticatedError::SessionError(
                SessionError::ReadSessionError,
            ))))
        });

        let app = Application::<MockAuthService, MockLichenService>::mock_instance(
            MockAppInstanceParameters {
                config: None,
                auth_service: Some(auth_service),
                lichen_service: None,
            },
        );

        let router = Router::new()
            .route("/example", get(example))
            .route_layer(from_fn_with_state(
                app,
                auth::<Application<MockAuthService, MockLichenService>>,
            ))
            .layer(session_layer);

        let server = TestServer::new(router).unwrap();

        let response = server.get("/example").await;

        response.assert_status_unauthorized();
    }

    #[tokio::test]
    async fn test_oidc_oidc_error() {
        let session_store = MemoryStore::default();
        let session_layer = SessionManagerLayer::new(session_store)
            .with_secure(false)
            .with_expiry(Expiry::OnInactivity(Duration::hours(1)))
            .with_same_site(SameSite::Lax);

        let mut auth_service = MockAuthService::new();
        auth_service.expect_authenticated().times(1).returning(|_| {
            Box::pin(future::ready(Err(
                ServiceAuthenticatedError::OIDCRefreshError(OIDCRefreshError::TokenDecodeError),
            )))
        });

        let app = Application::<MockAuthService, MockLichenService>::mock_instance(
            MockAppInstanceParameters {
                config: None,
                auth_service: Some(auth_service),
                lichen_service: None,
            },
        );

        let router = Router::new()
            .route("/example", get(example))
            .route_layer(from_fn_with_state(
                app,
                auth::<Application<MockAuthService, MockLichenService>>,
            ))
            .layer(session_layer);

        let server = TestServer::new(router).unwrap();

        let response = server.get("/example").await;

        response.assert_status_unauthorized();
    }
}

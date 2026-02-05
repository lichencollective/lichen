use crate::core::application::{Application, ApplicationServices};
use crate::domain::auth::AuthService;
use crate::domain::lichen::LichenService;
use crate::inbound::http::handlers::{
    oidc_callback, oidc_login, oidc_logout, oidc_profile, server_health,
};
use crate::inbound::http::middleware::auth;
use axum::Router;
use axum::extract::{MatchedPath, Request};
use axum::middleware::from_fn_with_state;
use axum::routing::get;
use axum_extra::extract::cookie::SameSite;
use http::header::{ACCEPT, ACCESS_CONTROL_ALLOW_ORIGIN, AUTHORIZATION, CONTENT_TYPE, ORIGIN};
use http::{HeaderValue, Method, StatusCode};
use time::Duration;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;
use tower_http::sensitive_headers::SetSensitiveHeadersLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tower_sessions::{Expiry, SessionManagerLayer, SessionStore};

pub fn router<
    AUTH: AuthService + Send + Sync + 'static,
    LICHEN: LichenService + Send + Sync + 'static,
    Store: SessionStore + Clone + Send + Sync + 'static,
>(
    application: Application<AUTH, LICHEN>,
    redis_session_store: Store,
) -> Router {
    let config = application.config();
    let same_site = if config.secure_session {
        SameSite::None
    } else {
        SameSite::Lax
    };
    let session_layer = SessionManagerLayer::new(redis_session_store)
        .with_secure(config.secure_session)
        .with_expiry(Expiry::OnInactivity(Duration::hours(1)))
        .with_same_site(same_site);
    // todo: secure cookies and None

    let hosts: Vec<HeaderValue> = config
        .cors_hosts
        .clone()
        .into_iter()
        .map(|host| host.parse().unwrap())
        .collect();

    let cors = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers(vec![
            ORIGIN,
            AUTHORIZATION,
            ACCEPT,
            CONTENT_TYPE,
            ACCESS_CONTROL_ALLOW_ORIGIN,
        ])
        .allow_origin(hosts)
        .allow_credentials(true);

    let oidc_routes = oidc_routes(application.clone());

    Router::new()
        .route("/healthz", get(server_health))
        .nest("/backend/oidc", oidc_routes)
        .layer(cors)
        .layer(session_layer)
        .layer((
            SetSensitiveHeadersLayer::new([AUTHORIZATION]),
            CompressionLayer::new(),
            TraceLayer::new_for_http()
                .make_span_with(|req: &Request| {
                    let method = req.method();
                    let uri = req.uri();

                    let matched_path = req
                        .extensions()
                        .get::<MatchedPath>()
                        .map(|matched_path| matched_path.as_str());

                    tracing::debug_span!("request", %method, %uri, matched_path)
                })
                .on_failure(()),
            TimeoutLayer::with_status_code(
                StatusCode::GATEWAY_TIMEOUT,
                std::time::Duration::from_secs(30),
            ),
            CatchPanicLayer::new(),
        ))
        .with_state(application)
}

fn oidc_routes<APP>(application: APP) -> Router<APP>
where
    APP: ApplicationServices + Send + Sync + 'static,
{
    let protected = Router::new()
        .route("/profile", get(oidc_profile::<APP>))
        .route_layer(from_fn_with_state(application, auth::<APP>));

    Router::new()
        .route("/login", get(oidc_login::<APP>))
        .route("/logout", get(oidc_logout::<APP>))
        .route("/callback", get(oidc_callback::<APP>))
        .merge(protected)
}

#[cfg(test)]
mod tests {
    use crate::core::config::Config;

    #[tokio::test]
    async fn test_secure_session_default_config() {
        let config = Config::default();
        assert_eq!(false, config.secure_session);
    }

    #[tokio::test]
    async fn test_secure_session_config() {
        let config = Config {
            secure_session: true,
            ..Default::default()
        };
        assert!(config.secure_session);
    }
}

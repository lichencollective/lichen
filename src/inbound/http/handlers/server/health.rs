use crate::inbound::http::responses::health::health_response;
use axum::Json;
use axum::response::IntoResponse;
use http::StatusCode;

pub async fn server_health() -> impl IntoResponse {
    let response = health_response();

    (StatusCode::OK, Json(response))
}

#[cfg(test)]
mod tests {
    use crate::core::application::Application;
    use crate::core::application::tests::MockAppInstanceParameters;
    use crate::domain::auth::MockAuthService;
    use crate::inbound::http::router;
    use axum_test::TestServer;
    use tower_sessions::MemoryStore;

    #[tokio::test]
    async fn test_server_health() {
        let app = Application::<MockAuthService>::mock_instance(MockAppInstanceParameters {
            config: None,
            auth_service: None,
        });
        let session_store = MemoryStore::default();
        let router = router(app, session_store);
        let server = TestServer::new(router).unwrap();

        let response = server.get("/healthz").await;

        response.assert_status_ok();
    }
}

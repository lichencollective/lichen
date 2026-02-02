use crate::domain::auth::ServiceProfileResult;
use crate::inbound::http::responses::shared::ResponseType;
use axum::Json;
use axum::response::{IntoResponse, Response};
use http::StatusCode;
use serde::Serialize;

#[derive(Serialize)]
pub struct ProfileResponse {
    data: ProfileData,
}

#[derive(Serialize)]
pub struct ProfileAttributes {
    groups: Vec<String>,
    username: Option<String>,
}

#[derive(Serialize)]
pub struct ProfileData {
    id: String,
    #[serde(rename = "type")]
    object_type: ResponseType,
    attributes: ProfileAttributes,
}

impl IntoResponse for ServiceProfileResult {
    fn into_response(self) -> Response {
        let response = ProfileResponse {
            data: ProfileData {
                id: self.user_id,
                attributes: ProfileAttributes {
                    groups: self.groups,
                    username: self.username,
                },
                object_type: ResponseType::Profile,
            },
        };

        (StatusCode::OK, Json(response)).into_response()
    }
}

use crate::inbound::http::responses::shared::ResponseType;
use serde::Serialize;

////////////////////////////////////////////////////////////////////////////////////////////////////
// Health
////////////////////////////////////////////////////////////////////////////////////////////////////

#[derive(Serialize)]
pub struct HealthResponse {
    data: HealthData,
    #[serde(rename = "type")]
    object_type: ResponseType,
}

#[derive(Serialize)]
pub struct HealthData {
    status: String,
}

pub fn health_response() -> HealthResponse {
    HealthResponse {
        data: HealthData {
            status: "OK".to_string(),
        },
        object_type: ResponseType::Health,
    }
}

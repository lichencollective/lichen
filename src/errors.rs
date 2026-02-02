use axum::Json;
use axum::response::{IntoResponse, Response};
use http::StatusCode;
use serde::Serialize;
use thiserror::Error;

#[derive(Serialize)]
pub struct AppErrorResponse {
    code: u16,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

#[derive(Error, Debug)]
pub enum AppError {
    #[error("auth required")]
    Unauthorized(Option<String>),

    #[error("internal server error")]
    InternalServerError,

    #[error("bad request")]
    BadRequest(Option<String>),

    #[error("user may not perform that action")]
    Forbidden,

    #[error("request path not found")]
    NotFound,

    #[error("request was rejected")]
    Rejected(Option<String>),
}

impl AppError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Rejected(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::Unauthorized(ref message) => (
                self.status_code(),
                Json(AppErrorResponse {
                    code: self.status_code().as_u16(),
                    status: self.to_string(),
                    message: message.clone(),
                }),
            )
                .into_response(),
            AppError::Forbidden => (
                self.status_code(),
                Json(AppErrorResponse {
                    code: self.status_code().as_u16(),
                    status: self.to_string(),
                    message: None,
                }),
            )
                .into_response(),
            AppError::NotFound => (
                self.status_code(),
                Json(AppErrorResponse {
                    code: self.status_code().as_u16(),
                    status: self.to_string(),
                    message: None,
                }),
            )
                .into_response(),
            AppError::BadRequest(ref message) => (
                self.status_code(),
                Json(AppErrorResponse {
                    code: self.status_code().as_u16(),
                    status: self.to_string(),
                    message: message.clone(),
                }),
            )
                .into_response(),
            AppError::InternalServerError => (
                self.status_code(),
                Json(AppErrorResponse {
                    code: self.status_code().as_u16(),
                    status: self.to_string(),
                    message: None,
                }),
            )
                .into_response(),
            AppError::Rejected(ref message) => (
                self.status_code(),
                Json(AppErrorResponse {
                    code: self.status_code().as_u16(),
                    status: self.to_string(),
                    message: message.clone(),
                }),
            )
                .into_response(),
        }
    }
}

pub fn internal_error<E: ToString>(err: E) -> AppError {
    tracing::error!("{}", err.to_string());
    AppError::InternalServerError
}

pub fn bad_request() -> AppError {
    AppError::BadRequest(None)
}

pub fn bad_request_invalid_session() -> AppError {
    AppError::BadRequest(Some("Invalid session".to_string()))
}

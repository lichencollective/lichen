use serde::Serialize;

#[derive(Serialize)]
pub enum ResponseType {
    #[serde(rename = "health")]
    Health,

    #[serde(rename = "profile")]
    Profile,
}

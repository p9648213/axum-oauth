use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub struct User {
    pub id: Uuid,
    pub account_id: String,
    pub username: String,
    pub image_url: Option<String>,
}

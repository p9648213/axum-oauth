use serde::{Deserialize, Serialize};

pub mod home;

#[derive(Deserialize, Serialize, Clone)]
pub struct User {
    username: String,
    image_url: Option<String>,
}

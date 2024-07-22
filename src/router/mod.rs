use auth_google::{callback, login};
use axum::{routing::get, Router};
use sqlx::{Pool, Sqlite};

pub mod auth_google;

#[derive(Debug, serde::Deserialize)]
pub struct AuthRequest {
    code: String,
    state: String,
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
pub struct GoogleUser {
    sub: String,
    name: String,
    email: Option<String>,
    email_verified: Option<bool>,
    picture: String,
}

pub fn google_auth_router(pool: Pool<Sqlite>) -> Router {
    Router::new()
        .route("/api/auth/google/login", get(login))
        .route("/api/auth/google/callback", get(callback))
        .with_state(pool)
}

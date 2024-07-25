use axum::{routing::get, Router};
use serde::Serialize;
use sqlx::{Pool, Sqlite};
use user::{get_user_info, logout};

pub mod user;

#[derive(Serialize, Debug)]
pub struct ResponeUser {
    pub username: String,
    pub image_url: Option<String>,
}

pub fn user_router(pool: Pool<Sqlite>) -> Router {
    Router::new()
        .route("/api/auth/me", get(get_user_info))
        .route("/api/auth/logout", get(logout))
        .with_state(pool)
}

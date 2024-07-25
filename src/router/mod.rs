use auth::google_auth_router;
use axum::{http::HeaderValue, routing::get, Router};
use sqlx::{Pool, Sqlite};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use user::user_router;

pub mod auth;
pub mod user;

pub fn create_router(pool: Pool<Sqlite>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin([
            "http://localhost:3000".parse::<HeaderValue>().unwrap(),
            "http://localhost:5173".parse::<HeaderValue>().unwrap(),
        ])
        .allow_credentials(true);

    Router::new()
        .route("/", get(ping))
        .merge(google_auth_router(pool.clone()))
        .merge(user_router(pool.clone()))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
}

async fn ping() -> &'static str {
    "pong"
}

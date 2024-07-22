use axum::{http::StatusCode, routing::get, Router};
use axum_oauth::helpers::app_error::AppError;
use dotenvy::dotenv;
use sqlx::SqlitePool;
use tower_http::trace::TraceLayer;
use tracing::Level;

#[tokio::main]
async fn main() -> Result<(), AppError> {
    dotenv().ok();
    
    tracing_subscriber::fmt().with_max_level(Level::DEBUG).init();

    let connection_string = std::env::var("DATABASE_URL").map_err(|error| {
        eprintln!("DATABASE_URL must be set: {}", error);
        AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "Server error")
    })?;

    let pool = SqlitePool::connect(&connection_string).await.map_err(|error| {
        eprintln!("Error connecting db pool: {}", error);
        AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "Server error")
    })?;

    let app = Router::new().route("/", get(ping)).with_state(pool).layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:5000").await.unwrap();
    axum::serve(listener, app).await.unwrap();

    Ok(())
}

async fn ping() -> &'static str {
    "pong"
}

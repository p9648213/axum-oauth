use axum::http::StatusCode;
use axum_oauth::{helpers::app_error::AppError, router::create_router};
use dotenvy::dotenv;
use sqlx::SqlitePool;
use tracing::Level;

#[tokio::main]
async fn main() -> Result<(), AppError> {
    dotenv().ok();

    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .init();

    let connection_string = std::env::var("DATABASE_URL").map_err(|error| {
        eprintln!("DATABASE_URL must be set: {}", error);
        AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "Server error")
    })?;

    let pool = SqlitePool::connect(&connection_string)
        .await
        .map_err(|error| {
            eprintln!("Error connecting db pool: {}", error);
            AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "Server error")
        })?;

    let app = create_router(pool);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:5000").await.unwrap();
    axum::serve(listener, app).await.unwrap();

    Ok(())
}

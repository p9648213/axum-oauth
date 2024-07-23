use reqwest::StatusCode;
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::{helpers::app_error::AppError, models::User};

pub async fn get_user_by_account_id(
    pool: &SqlitePool,
    account_id: String,
) -> Result<Option<User>, AppError> {
    let user = sqlx::query_as!(
        User,
        r#"
            SELECT id as "id: uuid::Uuid", account_id, username, image_url
            FROM user 
            WHERE account_id = ?1
        "#,
        account_id,
    )
    .fetch_optional(pool)
    .await
    .map_err(|error| {
        eprintln!("Error getting user: {}", error);
        AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "Server error")
    })?;

    Ok(user)
}

pub async fn create_user(
    pool: &SqlitePool,
    account_id: String,
    username: String,
    image_url: Option<String>,
) -> Result<User, AppError> {
    let id = Uuid::new_v4();
    let new_user = sqlx::query_as!(
        User,
        r#"
      INSERT INTO user (id, account_id, username, image_url) 
      VALUES (?1, ?2, ?3, ?4) 
      RETURNING id as "id: uuid::Uuid", account_id, username, image_url
    "#,
        id,
        account_id,
        username,
        image_url
    )
    .fetch_one(pool)
    .await
    .map_err(|error| {
        eprintln!("Error creating user: {}", error);
        AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "Server error")
    })?;

    Ok(new_user)
}

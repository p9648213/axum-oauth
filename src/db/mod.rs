use reqwest::StatusCode;
use sqlx::SqlitePool;
use std::{str::FromStr, time::Duration};
use uuid::Uuid;

use crate::{
    helpers::app_error::AppError,
    models::{User, UserSession},
};

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

pub async fn create_user_session(
    pool: &SqlitePool,
    user_id: Uuid,
    session_duration: Duration,
) -> Result<UserSession, AppError> {
    let session_id = Uuid::new_v4();
    let created_at = chrono::offset::Utc::now().naive_utc();
    let expires_at = created_at + session_duration;

    sqlx::query!(
        r#"
            INSERT INTO user_session (id, user_id, created_at, expires_at)
            VALUES (?1, ?2, ?3, ?4)
        "#,
        session_id,
        user_id,
        created_at,
        expires_at
    )
    .execute(pool)
    .await
    .map_err(|error| {
        eprintln!("Error creating user session: {}", error);
        AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "Server error")
    })?;

    let user_session = sqlx::query_as!(
        UserSession,
        r#"
            SELECT 
                id as "id: uuid::Uuid",
                user_id as "user_id: uuid::Uuid",
                created_at as "created_at: _",
                expires_at as "expires_at: _" 
            FROM user_session
            WHERE id = ?1
        "#,
        session_id
    )
    .fetch_one(pool)
    .await
    .map_err(|error| {
        eprintln!("Error getting user session: {}", error);
        AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "Server error")
    })?;

    Ok(user_session)
}

pub async fn get_user_by_session_id(
    pool: &SqlitePool,
    session_id: &str,
) -> Result<Option<User>, AppError> {
    let session_id = Uuid::from_str(session_id).map_err(|error| {
        eprintln!("Error convert session_id to uuid: {}", error);
        AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "Server Error")
    })?;

    let user = sqlx::query_as!(
        User,
        r#"
            SELECT user.id as "id: uuid::Uuid", account_id, username, image_url
            FROM user
            LEFT JOIN user_session AS session ON session.user_id = user.id
            WHERE session.id = ?1
        "#,
        session_id
    )
    .fetch_optional(pool)
    .await
    .map_err(|error| {
        eprintln!("Error fetching user: {}", error);
        AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "Server error")
    })?;

    if let Some(user) = &user {
        let deleted = delete_expired_user_session(pool, user.id).await?;

        if deleted > 0 {
            return Err(AppError::new(StatusCode::UNAUTHORIZED, "Session expire"));
        }
    }

    Ok(user)
}

pub async fn delete_expired_user_session(
    pool: &SqlitePool,
    user_id: Uuid,
) -> Result<usize, AppError> {
    let now = chrono::offset::Utc::now().naive_utc();
    let result = sqlx::query!(
        r#"
            DELETE FROM user_session 
            WHERE user_id = ?1 AND ?2 > expires_at
        "#,
        user_id,
        now
    )
    .execute(pool)
    .await
    .map_err(|error| {
        eprintln!("Error deleting user session: {}", error);
        AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "Server error")
    })?;

    Ok(result.rows_affected() as usize)
}

pub async fn delete_user_session(pool: &SqlitePool, session_id: &str) -> Result<bool, AppError> {
    let session_id = Uuid::from_str(session_id).map_err(|error| {
        eprintln!("Error convert session_id to uuid: {}", error);
        AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "Server Error")
    })?;

    let mut conn = pool.acquire().await.map_err(|error| {
        eprintln!("Error connection pool: {}", error);
        AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "Server error")
    })?;

    let result = sqlx::query!("DELETE FROM user_session WHERE id = ?1", session_id)
        .execute(&mut *conn)
        .await
        .map_err(|error| {
            eprintln!("Error deleting user session: {}", error);
            AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "Server error")
        })?;

    Ok(result.rows_affected() > 0)
}

use axum::{
    extract::State,
    response::{IntoResponse, Redirect},
    Json,
};
use axum_extra::extract::CookieJar;
use cookie::Cookie;
use reqwest::StatusCode;
use sqlx::SqlitePool;

use crate::{
    constants::COOKIE_AUTH_SESSION,
    db::{delete_user_session, get_user_by_session_id},
    helpers::app_error::AppError,
};

use super::ResponeUser;

pub async fn get_user_info(
    State(pool): State<SqlitePool>,
    cookies: CookieJar,
) -> Result<Json<ResponeUser>, AppError> {
    let session_cookie = cookies.get(COOKIE_AUTH_SESSION);

    let Some(session_cookie) = session_cookie else {
        tracing::error!("Invalid session");
        return Err(AppError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Server error",
        ));
    };

    let user = get_user_by_session_id(&pool, session_cookie.value()).await?;

    match user {
        Some(user) => {
            let response_user = ResponeUser {
                username: user.username,
                image_url: user.image_url,
            };

            Ok(Json(response_user))
        }
        None => Err(AppError::new(StatusCode::NOT_FOUND, "User not found")),
    }
}

pub async fn logout(
    State(pool): State<SqlitePool>,
    mut cookies: CookieJar,
) -> Result<impl IntoResponse, AppError> {
    let session_cookie = cookies.get(COOKIE_AUTH_SESSION);

    let Some(session_cookie) = session_cookie else {
        return Err(AppError::new(StatusCode::UNAUTHORIZED, "Unauthorized"));
    };

    delete_user_session(&pool, session_cookie.value()).await?;

    let mut remove_session_cookie = Cookie::new(COOKIE_AUTH_SESSION, "");
    remove_session_cookie.set_path("/");
    remove_session_cookie.make_removal();

    cookies = cookies.add(remove_session_cookie);
    Ok((cookies, Redirect::to("http://localhost:5000")))
}

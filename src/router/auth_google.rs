use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect},
};
use axum_extra::extract::CookieJar;
use cookie::Cookie;
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthUrl, AuthorizationCode, ClientId,
    ClientSecret, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    TokenResponse, TokenUrl,
};
use sqlx::SqlitePool;

use crate::{
    constants::{COOKIE_AUTH_CODE_VERIFIER, COOKIE_AUTH_CSRF_STATE},
    db::{create_user, get_user_by_account_id},
    helpers::app_error::AppError,
    router::GoogleUser,
};

use super::AuthRequest;

fn get_oauth_client() -> Result<BasicClient, AppError> {
    let client_id = ClientId::new(std::env::var("GOOGLE_CLIENT_ID").map_err(|_| {
        AppError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "GOOGLE_CLIENT_ID missing",
        )
    })?);

    let client_secret = ClientSecret::new(std::env::var("GOOGLE_CLIENT_SECRET").map_err(|_| {
        AppError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "GOOGLE_CLIENT_SECRET missing",
        )
    })?);

    let auth_url = AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
        .map_err(|_| {
            AppError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Invalid authorization endpoint URL",
            )
        })?;

    let token_url = TokenUrl::new("https://www.googleapis.com/oauth2/v3/token".to_string())
        .map_err(|_| {
            AppError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Invalid token endpoint URL",
            )
        })?;

    let base_url = "http://localhost:5000".to_string();

    let redirect_url = RedirectUrl::new(format!("{base_url}/api/auth/google/callback"))
        .map_err(|_| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "Invalid redirect url"))?;

    let client = BasicClient::new(client_id, Some(client_secret), auth_url, Some(token_url))
        .set_redirect_uri(redirect_url);

    Ok(client)
}

pub async fn login() -> Result<impl IntoResponse, AppError> {
    let client = get_oauth_client()?;

    let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();

    let (authorize_url, csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new(
            "https://www.googleapis.com/auth/userinfo.profile".to_string(),
        ))
        .set_pkce_challenge(pkce_code_challenge)
        .url();

    // Set csrf and code verifier cookies, these are short lived cookies
    let cookie_max_age = cookie::time::Duration::minutes(5);
    let crsf_cookie: Cookie =
        Cookie::build((COOKIE_AUTH_CSRF_STATE, csrf_state.secret().to_owned()))
            .http_only(true)
            .path("/")
            .same_site(cookie::SameSite::Lax)
            .max_age(cookie_max_age)
            .into();

    let code_verifier: Cookie = Cookie::build((
        COOKIE_AUTH_CODE_VERIFIER,
        pkce_code_verifier.secret().to_owned(),
    ))
    .http_only(true)
    .path("/")
    .same_site(cookie::SameSite::Lax)
    .max_age(cookie_max_age)
    .into();

    let cookies = CookieJar::new().add(crsf_cookie).add(code_verifier);

    Ok((cookies, Redirect::to(authorize_url.as_str())))
}

pub async fn callback(
    State(pool): State<SqlitePool>,
    Query(query): Query<AuthRequest>,
    cookies: CookieJar,
) -> Result<impl IntoResponse, AppError> {
    let code = query.code;
    let state = query.state;
    let stored_state = cookies.get(COOKIE_AUTH_CSRF_STATE);
    let stored_code_verifier = cookies.get(COOKIE_AUTH_CODE_VERIFIER);

    let (Some(csrf_state), Some(code_verifier)) = (stored_state, stored_code_verifier) else {
        return Ok(StatusCode::BAD_REQUEST.into_response());
    };

    if csrf_state.value() != state {
        return Ok(StatusCode::BAD_REQUEST.into_response());
    }

    let client = get_oauth_client()?;
    let code = AuthorizationCode::new(code);
    let pkce_code_verifier = PkceCodeVerifier::new(code_verifier.value().to_owned());

    let token_response = client
        .exchange_code(code)
        .set_pkce_verifier(pkce_code_verifier)
        .request_async(async_http_client)
        .await
        .map_err(|_| {
            AppError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get token response",
            )
        })?;

    // Get the Google user info
    let google_user = reqwest::Client::new()
        .get("https://www.googleapis.com/oauth2/v3/userinfo")
        .bearer_auth(token_response.access_token().secret())
        .send()
        .await
        .map_err(|_| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "Failed to get user info"))?
        .json::<GoogleUser>()
        .await
        .map_err(|_| {
            AppError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to convert user info to Json",
            )
        })?;

    // Add user session
    let account_id = google_user.sub.clone();
    let existing_user = get_user_by_account_id(&pool, account_id.clone()).await?;

    let user = match existing_user {
        Some(x) => x,
        None => {
            create_user(
                &pool,
                account_id,
                google_user.name,
                Some(google_user.picture),
            )
            .await?
        }
    };

    todo!()
}

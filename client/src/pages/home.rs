use super::User;
use leptos::*;


#[component]
pub fn HomePage() -> impl IntoView {
    let (user, set_user) = create_signal::<Option<User>>(None);

    create_effect(move |_| {
        spawn_local(async move {
            let user = get_user().await.map_err(|error| error.to_string());
            match user {
                Ok(user) => {
                    set_user(Some(user));
                },
                Err(error) => {
                    logging::log!("{}", error);
                    set_user(None);
                },
            }
        });
    });

    view! {
        <div class="container">
            <Show
                when=move || match user.get() {
                    Some(_) => false,
                    None => true,
                }

                fallback=move || {
                    view! {
                        <div>
                            <div>
                                <p>{move || user.get().unwrap().username}</p>
                                <img src=move || user.get().unwrap().image_url alt="avatar"/>
                            </div>
                            <a
                                class="login-button dark"
                                href="http://localhost:5000/api/auth/logout"
                            >
                                <img alt="Google Logo" src="/google-logo.png"/>
                                <span>"Logout"</span>
                            </a>
                        </div>
                    }
                }
            >

                <div>
                    <a class="login-button dark" href="http://localhost:5000/api/auth/google/login">
                        <img alt="Google Logo" src="/google-logo.png"/>
                        <span>"Login with Google"</span>
                    </a>
                </div>
            </Show>
        </div>
    }
}

#[server(GetUser, "/user")]
async fn get_user() -> Result<User, ServerFnError<String>> {
    use leptos_axum::*;
    use http::HeaderMap;

    let headers = extract::<HeaderMap>().await.map_err(|error| ServerFnError::ServerError(error.to_string()))?;
    let cookie = headers.get("Cookie");

    let cookie = match cookie {
        Some(cookie) =>  cookie.to_str().unwrap_or(""),
        None => return Err(ServerFnError::ServerError("Session not found".to_owned()))
    };

    let client = reqwest_wasm::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();

    let response = client
        .get("http://localhost:5000/api/auth/me")
        .header("Cookie", cookie)
        .send()
        .await
        .map_err(|error| ServerFnError::ServerError(error.to_string()))?;

    let body = response
        .text()
        .await
        .map_err(|error| ServerFnError::ServerError(error.to_string()))?;

    let user: User = serde_json::from_str(&body)
        .map_err(|error| ServerFnError::ServerError(error.to_string()))?;

    Ok(user)
}

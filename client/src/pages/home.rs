use super::User;
use leptos::*;

#[component]
pub fn HomePage() -> impl IntoView {
    create_effect(|_| {
        spawn_local(async {
            let _ = get_user().await.map_err(|err| logging::log!("{:?}", err));
        });
    });

    // let user_data = create_resource(|| (), |_| async move { get_user().await });

    // view! {
    //     <div class="container">
    //         <h1>"Oauth"</h1>
    //         <div>
    //             <Suspense fallback=move || view! {}>
    //                 {
    //                     move || match user_data.get() {
    //                         Some(user) => {
    //                             match user {
    //                                 Ok(user) => view! {
    //                                     <div>
    //                                         <img src=user.image_url.unwrap_or("".to_string()) alt="user_logo" />
    //                                         <p>{user.username}</p>
    //                                     </div>
    //                                 }.into_view(),
    //                                 Err(error) => view! {
    //                                     <a class="login-button dark" href="http://localhost:5000/api/auth/google/login">
    //                                         <img alt="Google Logo" src="/google-logo.png"/>
    //                                         <span>"Login with Google"</span>
    //                                     </a>
    //                                     <div>{error}</div>
    //                                 }.into_view()
    //                             }
    //                         },
    //                         None => view! {}.into_view(),
    //                     }
    //                 }
    //             </Suspense>
    //         </div>
    //     </div>
    // }
    view! {
        <a class="login-button dark" href="http://localhost:5000/api/auth/google/login">
            <img alt="Google Logo" src="/google-logo.png"/>
            <span>"Login with Google"</span>
        </a>
    }
}

#[server(GetUser, "/user")]
async fn get_user() -> Result<User, ServerFnError<String>> {
    let client = reqwest_wasm::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();

    let response = client
        .get("http://localhost:5000/api/auth/me")
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

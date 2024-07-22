use leptos::*;

#[component]
pub fn HomePage() -> impl IntoView {
    view! {
        <div class="container">
            <h1>"Oauth"</h1>
            <div>
                <a class="login-button dark" href="/api/auth/google/login">
                    <img alt="Google Logo" src="/google-logo.png"/>
                    <span>"Login with Google"</span>
                </a>
            </div>
        </div>
    }
}

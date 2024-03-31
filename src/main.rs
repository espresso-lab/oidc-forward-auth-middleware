use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType};
use openidconnect::reqwest::http_client;
use openidconnect::{
    AuthenticationFlow, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, RedirectUrl, Scope,
};
use salvo::http::StatusCode;
use salvo::prelude::*;
use std::env;

#[derive(Clone)]
struct OIDCProvider {
    hostname: String,
    client_id: ClientId,
    client_secret: ClientSecret,
    issuer_url: IssuerUrl,
}

fn get_env(key: &str, default: Option<&str>) -> String {
    env::var(key).unwrap_or_else(|_| default.unwrap_or("").to_owned())
}

fn get_oidc_providers() -> Vec<OIDCProvider> {
    let hostnames = get_env("AUTH_HOSTNAMES", None);
    let provider_urls = get_env("AUTH_PROVIDER_URLS", None);
    let client_ids = get_env("AUTH_CLIENT_IDS", None);
    let secrets = get_env("AUTH_SECRETS", None);
    let (hostnames, urls, clients, secrets) = (
        hostnames.split(",").collect::<Vec<_>>(),
        provider_urls.split(",").collect::<Vec<_>>(),
        client_ids.split(",").collect::<Vec<_>>(),
        secrets.split(",").collect::<Vec<_>>(),
    );

    urls.iter()
        .enumerate()
        .map(|(index, url)| OIDCProvider {
            hostname: hostnames.get(index).unwrap().to_string().to_lowercase(),
            client_id: ClientId::new(clients.get(index).unwrap().to_string()),
            client_secret: ClientSecret::new(secrets.get(index).unwrap().to_string()),
            issuer_url: IssuerUrl::new(url.to_string()).expect("Invalid issuer URL"),
        })
        .collect()
}

fn get_oidc_provider_for_hostname(hostname: String) -> Option<OIDCProvider> {
    get_oidc_providers()
        .iter()
        .find(|provider| provider.hostname == hostname)
        .cloned()
}

#[handler]
async fn forward_auth_handler(req: &mut Request, res: &mut Response) {
    let hostname = req
        .headers()
        .get("X-Forwarded-Host")
        .expect("X-Forwarded-Host needed")
        .to_str()
        .unwrap_or("")
        .to_string();
    let oidc_provider = match get_oidc_provider_for_hostname(hostname.clone()) {
        Some(val) => val,
        None => {
            return res
                .status_code(StatusCode::BAD_GATEWAY)
                .render(Text::Plain("No OIDC provider known for hostname."))
        }
    };

    let provider_metadata =
        CoreProviderMetadata::discover(&oidc_provider.issuer_url, http_client).unwrap();
    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        oidc_provider.client_id,
        Some(oidc_provider.client_secret),
    )
    .set_redirect_uri(
        RedirectUrl::new(format!("https://{}/auth_callback", hostname.clone()).to_string())
            .expect("Invalid redirect URL"),
    );

    let (authorize_url, _, _) = client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .url();

    res.render(Redirect::temporary(authorize_url.to_string()));
}

#[handler]
async fn status_handler(res: &mut Response) {
    res.status_code(StatusCode::OK).render(Text::Plain("OK"));
}

#[handler]
async fn ok_handler(res: &mut Response) {
    res.status_code(StatusCode::OK)
        .render(Text::Plain("OK Handler"));
}

#[handler]
async fn set_cookie(res: &mut Response) {
    println!("Set Cookie");
    //res.status_code(StatusCode::OK).render(Text::Html("Ok. ✅"));
}

#[handler]
async fn check_cookie(res: &mut Response) {
    println!("Check Cookie");
    //res.status_code(StatusCode::N).render(Text::Html("Ok. ✅"));
}

#[handler]
async fn check_params(res: &mut Response) {
    println!("Check Params");
    //res.status_code(StatusCode::OK).render(Text::Html("Ok. ✅"));
}

#[tokio::main]
async fn main() {
    let router = Router::new()
        .push(Router::with_path("/status").get(status_handler))
        .push(
            Router::with_path("/verify")
                .push(Router::new().hoop(check_cookie).get(ok_handler))
                .push(
                    Router::new()
                        .hoop(check_params)
                        .hoop(set_cookie)
                        .get(ok_handler),
                )
                .push(Router::new().get(forward_auth_handler)),
        );

    let acceptor = TcpListener::new("0.0.0.0:3000").bind().await;
    println!("Starting server on http://0.0.0.0:3000");
    Server::new(acceptor).serve(router).await;
}

use openidconnect::core::{
    CoreClient, CoreIdTokenClaims, CoreIdTokenVerifier, CoreProviderMetadata, CoreResponseType,
};
use openidconnect::reqwest::http_client;
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    NonceVerifier, OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
};
use querystring::querify;
use salvo::http::cookie::Cookie;
use salvo::http::StatusCode;
use salvo::prelude::*;
use std::env;

fn handle_error<T: std::error::Error>(fail: &T, msg: &'static str) {
    let mut err_msg = format!("ERROR: {}", msg);
    let mut cur_fail: Option<&dyn std::error::Error> = Some(fail);
    while let Some(cause) = cur_fail {
        err_msg += &format!("\ncaused by: {}", cause);
        cur_fail = cause.source();
    }
    println!("{}", err_msg);
}

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

    // Generate a PKCE challenge.
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (authorize_url, csrf_state, nonce) = client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    // Set Cookies
    res.add_cookie(Cookie::new(
        "pkce_verifier",
        pkce_verifier.secret().to_string(),
    ));
    res.add_cookie(Cookie::new("csrf_state", csrf_state.secret().to_string()));
    res.add_cookie(Cookie::new("nonce", nonce.secret().to_string()));

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
async fn check_cookie(req: &mut Request, res: &mut Response) {
    let cookie_name = get_env("FORWARD_AUTH_COOKIE", Some("forward_auth"));
    let cookie_value = req.cookie(cookie_name);
    if cookie_value.is_none() {
        return res
            .status_code(StatusCode::UNAUTHORIZED)
            .render(Text::Plain("Unauthorized"));
    }
    // TODO: Validate token (JWT)
}

#[handler]
async fn check_params(req: &mut Request, res: &mut Response) {
    println!("asd");
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
    );

    // let id_token_verifier: CoreIdTokenVerifier = client.id_token_verifier();
    let pkce_verifier = PkceCodeVerifier::new(req.cookie("pkce_verifier").unwrap().to_string());
    let csrf_state = CsrfToken::new(req.cookie("csrf_state").unwrap().to_string());

    println!("CSRF State: {:?}", csrf_state.secret());
    println!("PKCE Verifier: {:?}", pkce_verifier.secret());
    println!("Hostname: {:?}", hostname);

    // // Exchange the code with a token.
    // let token_response = client
    //     .exchange_code(AuthorizationCode::new(
    //         req.query("code").expect("Code not found").to_string(),
    //     ))
    //     .set_pkce_verifier(pkce_verifier)
    //     .request(http_client)
    //     .unwrap_or_else(|err| {
    //         handle_error(&err, "Failed to contact token endpoint");
    //         unreachable!();
    //     });

    // println!(
    //     "access token:\n{}\n",
    //     token_response.access_token().secret()
    // );
    // println!("SCOPES: {:?}", token_response.scopes());

    // let nonce = Nonce::new(
    //     req.cookie("nonce")
    //         .expect("Nonce cookie not found")
    //         .value()
    //         .to_string(),
    // );

    // let id_token_claims: &CoreIdTokenClaims = token_response
    //     .extra_fields()
    //     .id_token()
    //     .expect("Server did not return an ID token")
    //     .claims(&id_token_verifier, nonce_verifier)
    //     .unwrap_or_else(|err| {
    //         handle_error(&err, "Failed to verify ID token");
    //         unreachable!();
    //     });

    // println!("ID token: {:?}\n", id_token_claims);

    res.status_code(StatusCode::NO_CONTENT);
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

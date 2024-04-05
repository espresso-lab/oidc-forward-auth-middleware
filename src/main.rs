use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType};
use openidconnect::reqwest::http_client;
use openidconnect::url::Url;
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use salvo::http::cookie::Cookie;
use salvo::http::StatusCode;
use salvo::prelude::*;
use salvo::routing::PathState;
use std::collections::HashMap;
use std::env;

// Define a struct to hold OIDC provider information
#[derive(Clone)]
struct OIDCProvider {
    hostname: String,
    client_id: ClientId,
    client_secret: ClientSecret,
    issuer_url: IssuerUrl,
}

// Function to get environment variables
fn get_env(key: &str, default: Option<&str>) -> String {
    env::var(key).unwrap_or_else(|_| default.unwrap_or("").to_owned())
}

// Function to get headers from request
fn get_header(req: &Request, key: &str) -> String {
    req.headers()
        .get(key)
        .expect(format!("{} needed", key).as_str())
        .to_str()
        .unwrap_or("")
        .to_string()
}

// Function to get query parameters from query string
fn get_query_param(querystring: &str, key: &str) -> String {
    let hash_query: HashMap<String, String> =
        Url::parse(format!("https://whatever{}", querystring).as_str())
            .unwrap()
            .query_pairs()
            .into_owned()
            .collect();
    hash_query.get(key).unwrap_or(&"".to_string()).to_owned()
}

// Function to get OIDC providers from environment variables
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

// Function to get OIDC provider for a given hostname
fn get_oidc_provider_for_hostname(hostname: String) -> Option<OIDCProvider> {
    get_oidc_providers()
        .iter()
        .find(|provider| provider.hostname == hostname)
        .cloned()
}

// Handler for forwarding authentication
#[handler]
async fn forward_auth_handler(req: &mut Request, res: &mut Response) {
    let hostname = get_header(req, "x-forwarded-host");
    let proto = get_header(req, "x-forwarded-proto");
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
        RedirectUrl::new(format!("{}://{}/auth_callback", proto, hostname.clone()).to_string())
            .expect("Invalid redirect URL"),
    );

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (authorize_url, csrf_state, _nonce) = client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    res.add_cookie(Cookie::new("csrf_state", csrf_state.secret().to_string()));
    res.add_cookie(Cookie::new(
        "pkce_verifier",
        pkce_verifier.secret().to_string(),
    ));

    res.render(Redirect::temporary(authorize_url.to_string()));
}

// Handler for OK response
#[handler]
async fn ok_handler(res: &mut Response) {
    res.status_code(StatusCode::OK).render(Text::Plain("OK"));
}

// Function to check if a cookie exists
fn check_cookie(req: &mut Request, _state: &mut PathState) -> bool {
    let cookie_name = get_env("FORWARD_AUTH_COOKIE", Some("forward_auth"));
    req.cookie(cookie_name).is_some()
}

// Function to check parameters
fn check_params(req: &mut Request, _state: &mut PathState) -> bool {
    let uri = get_header(req, "x-forwarded-uri");
    let csrf_state = req.cookie("csrf_state").unwrap().value();
    let code = get_query_param(&uri, "code");
    let state = get_query_param(&uri, "state");

    if uri.is_empty()
        || code.is_empty()
        || state.is_empty()
        || csrf_state.is_empty()
        || state != csrf_state
    {
        return false;
    }

    let hostname = get_header(req, "x-forwarded-host");
    if !match get_oidc_provider_for_hostname(hostname.clone()) {
        Some(_val) => true,
        None => {
            return false;
        }
    } {
        return false;
    }

    true
}

// Set the final cookie here
#[handler]
async fn set_cookie(req: &mut Request, res: &mut Response) {
    let uri = get_header(req, "x-forwarded-uri");
    let hostname = get_header(req, "x-forwarded-host");
    let proto = get_header(req, "x-forwarded-proto");
    let code = get_query_param(&uri, "code");
    let pkce_verifier = req.cookie("pkce_verifier").unwrap().value().to_owned();

    if code.is_empty() {
        return res
            .status_code(StatusCode::BAD_GATEWAY)
            .render(Text::Plain("No Token in response."));
    }

    let oidc_provider = match get_oidc_provider_for_hostname(hostname.clone()) {
        Some(val) => val,
        None => {
            return res
                .status_code(StatusCode::BAD_GATEWAY)
                .render(Text::Plain("No OIDC provider known for hostname."));
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
        RedirectUrl::new(format!("{}://{}/auth_callback", proto, hostname.clone()).to_string())
            .expect("Invalid redirect URL"),
    );

    let token_response = client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier))
        .request(http_client)
        .unwrap();

    let id_token = token_response.id_token().unwrap().clone().to_string();
    let access_token = token_response.access_token().secret().to_string();

    println!("ID Token: {:?}", id_token);
    println!("Access Token: {:?}", access_token);

    let cookie_name = get_env("FORWARD_AUTH_COOKIE", Some("forward_auth"));
    res.add_cookie(Cookie::new(cookie_name, access_token));
    res.remove_cookie("csrf_state");
    res.remove_cookie("pkce_verifier");

    res.render(Redirect::temporary(format!(
        "https://{}/",
        hostname.clone()
    )));
}

// Enhance the security
#[handler]
async fn apply_security_headers(req: &mut Request, res: &mut Response) {
    // match  req
    //     .headers()
    //     .get("x-forwarded-host")
    //     .expect("x-forwarded-host needed")
    //     .to_str()
    //     .unwrap_or("")
    //     .to_string() {
    //         Some(x) ||
    //     }
    // TODO
    // let hostname = req
    //     .headers()
    //     .get("x-forwarded-host")
    //     .expect("x-forwarded-host needed")
    //     .to_str()
    //     .unwrap_or("")
    //     .to_string();

    // if hostname != "localhost" {
    //     res.headers_mut()
    //         .insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));

    //     res.headers_mut().insert(
    //         STRICT_TRANSPORT_SECURITY,
    //         HeaderValue::from_static("max-age=2592000"),
    //     );
    // }
}

#[tokio::main]
async fn main() {
    let router = Router::new()
        .hoop(apply_security_headers)
        .push(Router::with_path("/status").get(ok_handler))
        .push(
            Router::with_path("/verify")
                .push(Router::with_filter_fn(check_cookie).goal(ok_handler))
                .push(
                    Router::with_filter_fn(check_params)
                        .hoop(set_cookie)
                        .goal(ok_handler),
                )
                .push(Router::new().goal(forward_auth_handler)),
        );
    let acceptor = TcpListener::new("0.0.0.0:3000").bind().await;
    Server::new(acceptor).serve(router).await;
}

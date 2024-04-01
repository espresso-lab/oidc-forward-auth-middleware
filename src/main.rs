use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType};
use openidconnect::reqwest::http_client;
use openidconnect::url::Url;
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    PkceCodeChallenge, RedirectUrl, Scope, TokenResponse,
};
use salvo::http::cookie::Cookie;
use salvo::http::StatusCode;
use salvo::prelude::*;
use salvo::routing::PathState;
use std::collections::HashMap;
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
    // get hostname
    let hostname = req
        .headers()
        .get("x-forwarded-host")
        .expect("x-forwarded-host needed")
        .to_str()
        .unwrap_or("")
        .to_string();

    // get proto
    let proto = req
        .headers()
        .get("x-forwarded-proto")
        .expect("x-forwarded-proto needed")
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
        RedirectUrl::new(
            format!("{}://{}/auth_callback", proto.clone(), hostname.clone()).to_string(),
        )
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
        // .set_pkce_challenge(pkce_challenge)
        .url();

    // print auth url
    println!("Authorize URL: {:?}", authorize_url);

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
async fn ok_handler(res: &mut Response) {
    res.status_code(StatusCode::OK).render(Text::Plain("OK"));
}

#[handler]
async fn set_cookie(_res: &mut Response) {
    println!("Set Cookie");
    //res.status_code(StatusCode::OK).render(Text::Html("Ok. ✅"));
}

fn check_cookie(req: &mut Request, _state: &mut PathState) -> bool {
    let cookie_name = get_env("FORWARD_AUTH_COOKIE", Some("forward_auth"));
    let cookie_value = req.cookie(cookie_name);
    if cookie_value.is_none() {
        return false;
    }
    return true;
    // TODO: Check if cookie is valid.
}

fn check_params(req: &mut Request, _state: &mut PathState) -> bool {
    // get uri
    let uri = req
        .headers()
        .get("x-forwarded-uri")
        .expect("x-forwarded-uri needed")
        .to_str()
        .unwrap_or("")
        .to_string();

    // get parameters
    let hash_query: HashMap<String, String> =
        Url::parse(format!("http://localhost{}", uri).as_str())
            .unwrap()
            .query_pairs()
            .into_owned()
            .collect();

    let code = hash_query
        .get("code")
        .unwrap_or(&"".to_string())
        .to_string();

    if code.is_empty() {
        return false;
    }

    let csrf_state = req.cookie("csrf_state").unwrap().value();
    let pkce_verifier = req.cookie("pkce_verifier").unwrap().value();
    let nonce_verifier = req.cookie("nonce").unwrap().value();

    println!("code: {:?}", code);
    println!("csrf_state: {:?}", csrf_state);
    println!("pkce_verifier: {:?}", pkce_verifier);
    println!("nonce_verifier: {:?}", nonce_verifier);

    // get hostname
    let hostname = req
        .headers()
        .get("x-forwarded-host")
        .expect("x-forwarded-host needed")
        .to_str()
        .unwrap_or("")
        .to_string();

    let oidc_provider = match get_oidc_provider_for_hostname(hostname.clone()) {
        Some(val) => val,
        None => {
            return false;
        }
    };

    let provider_metadata =
        CoreProviderMetadata::discover(&oidc_provider.issuer_url, http_client).unwrap();

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        oidc_provider.client_id,
        Some(oidc_provider.client_secret),
    );

    // let pkce_verifier = PkceCodeVerifier::new(pkce_verifier.to_owned());
    // let csrf_state = CsrfToken::new(csrf_state);

    // Exchange the code with a token.
    let token_response = client
        .exchange_code(AuthorizationCode::new(code))
        // .set_pkce_verifier(pkce_verifier)
        .request(http_client)
        .unwrap();

    let id_token = token_response.id_token().unwrap();

    println!("ID token: {:?}\n", id_token);
    return true;
}

#[tokio::main]
async fn main() {
    let router = Router::new()
        .push(Router::with_path("/status").get(ok_handler))
        .push(
            Router::with_path("/verify")
                .push(Router::with_filter_fn(check_cookie).get(ok_handler))
                .push(
                    Router::with_filter_fn(check_params)
                        .hoop(set_cookie)
                        .get(ok_handler),
                )
                .push(Router::new().get(forward_auth_handler)),
        );

    let acceptor = TcpListener::new("0.0.0.0:3000").bind().await;
    println!("Starting server on http://0.0.0.0:3000");
    Server::new(acceptor).serve(router).await;
}

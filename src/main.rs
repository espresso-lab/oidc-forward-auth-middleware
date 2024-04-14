use once_cell::sync::Lazy;
use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType};
use openidconnect::reqwest::http_client;
use openidconnect::url::Url;
use openidconnect::{
    AccessToken, AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    IntrospectionUrl, IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, Scope, TokenIntrospectionResponse, TokenResponse,
};
use salvo::http::cookie::Cookie;
use salvo::http::StatusCode;
use salvo::prelude::*;
use salvo::routing::PathState;
use std::collections::HashMap;
use std::env;

static PROVIDERS: Lazy<HashMap<String, OIDCProvider>> = Lazy::new(|| get_oidc_providers());

// Define a struct to hold OIDC provider information
#[derive(Clone)]
struct OIDCProvider {
    client_id: ClientId,
    client_secret: ClientSecret,
    issuer_url: IssuerUrl,
    scopes: Vec<String>,
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

// Function to get cookie from request
fn get_cookie(req: &Request, key: &str) -> String {
    req.cookie(key)
        .unwrap_or(&Cookie::new(key, ""))
        .value()
        .to_string()
}

// Function to get OIDC providers from environment variables
fn get_oidc_providers() -> HashMap<String, OIDCProvider> {
    let mut providers = HashMap::new();

    for i in 0u32.. {
        let hostname = get_env(&format!("OIDC_PROVIDER_{}_HOSTNAME", i), None);
        let issuer_url = get_env(&format!("OIDC_PROVIDER_{}_ISSUER_URL", i), None);
        let client_id = get_env(&format!("OIDC_PROVIDER_{}_CLIENT_ID", i), None);
        let client_secret = get_env(&format!("OIDC_PROVIDER_{}_CLIENT_SECRET", i), None);
        let scopes = get_env(&format!("OIDC_PROVIDER_{}_SCOPES", i), None);

        if hostname.is_empty()
            || issuer_url.is_empty()
            || client_id.is_empty()
            || client_secret.is_empty()
        {
            break;
        }

        providers.insert(
            hostname.to_lowercase(),
            OIDCProvider {
                client_id: ClientId::new(client_id),
                client_secret: ClientSecret::new(client_secret),
                issuer_url: IssuerUrl::new(issuer_url.to_string()).expect("Invalid issuer URL"),
                scopes: scopes.split(',').map(String::from).collect(),
            },
        );
    }

    providers
}

// Function to get OIDC provider for a given hostname
fn get_oidc_provider_for_hostname(hostname: String) -> Option<OIDCProvider> {
    PROVIDERS.get(&hostname.to_lowercase()).cloned()
}

// TODO: Save providers and provider metadata to a global variable and update it e.g. once per day

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
        .add_scope(Scope::new("email".to_string())) // TODO: take from oidc_provider.scopes
        .add_scope(Scope::new("profile".to_string())) // TODO: take from oidc_provider.scopes
        .set_pkce_challenge(pkce_challenge)
        .url();

    res.add_cookie(
        Cookie::build(("pkce_verifier", pkce_verifier.secret().to_string()))
            .secure(proto == "https")
            .build(),
    );
    res.add_cookie(
        Cookie::build(("csrf_state", csrf_state.secret().to_string()))
            .secure(proto == "https")
            .build(),
    );

    res.render(Redirect::temporary(authorize_url.to_string()));
}

// Handler for OK response
#[handler]
async fn ok_handler(res: &mut Response) {
    res.status_code(StatusCode::OK).render(Text::Plain("OK"));
}

// Function to check if a cookie exists
fn check_cookie(req: &mut Request, _state: &mut PathState) -> bool {
    let hostname = get_header(req, "x-forwarded-host");
    let proto = get_header(req, "x-forwarded-proto");
    let cookie_name = get_env("FORWARD_AUTH_COOKIE", Some("x_forward_auth_session"));
    let cookie = get_cookie(req, &cookie_name);
    if cookie.is_empty() {
        return false;
    }
    // verify the cookie here
    let oidc_provider = match get_oidc_provider_for_hostname(hostname.clone()) {
        Some(val) => val,
        None => return false,
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
    )
    .set_introspection_uri(
        IntrospectionUrl::new(oidc_provider.issuer_url.url().to_string())
            .expect("Invalid redirect URL"),
    );

    // TODO: Uncomment; Comment it in to make site still accesible
    // Implement access token introspection here
    // let res = client
    //     .introspect(&AccessToken::new(cookie))
    //     .unwrap()
    //     .request(http_client)
    //     .unwrap();

    // res.active()

    true
}

// Function to check parameters
fn check_params(req: &mut Request, _state: &mut PathState) -> bool {
    let uri = get_header(req, "x-forwarded-uri");
    let csrf_state = get_cookie(req, "csrf_state");
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
    let pkce_verifier = get_cookie(req, "pkce_verifier");

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

    let cookie_name = get_env("FORWARD_AUTH_COOKIE", Some("x_forward_auth_session"));
    res.add_cookie(
        Cookie::build((cookie_name, access_token))
            .secure(proto == "https")
            .build(),
    );
    res.remove_cookie("csrf_state");
    res.remove_cookie("pkce_verifier");

    res.render(Redirect::temporary(format!(
        "https://{}/",
        hostname.clone()
    )));
}

// Enhance the security
#[handler]
async fn apply_security_headers(_req: &mut Request, _res: &mut Response) {
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

use std::collections::HashMap;
use std::env;

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use once_cell::sync::Lazy;
use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType};
use openidconnect::reqwest::http_client;
use openidconnect::url::Url;
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use salvo::http::cookie::Cookie;
use salvo::http::StatusCode;
use salvo::prelude::{handler, Redirect, Request, Response, Router, Server, TcpListener, Text};
use salvo::routing::PathState;
use salvo::Listener;
use serde::{Deserialize, Serialize};

static PROVIDERS: Lazy<HashMap<String, OIDCProvider>> = Lazy::new(|| get_oidc_providers());

#[derive(Clone)]
struct OIDCProvider {
    client_id: ClientId,
    client_secret: ClientSecret,
    issuer_url: IssuerUrl,
    scopes: Vec<String>,
    jwks: JwkSet,
}

fn get_env(key: &str, default: Option<&str>) -> String {
    env::var(key).unwrap_or_else(|_| default.unwrap_or("").to_owned())
}

fn get_header(req: &Request, key: &str) -> String {
    req.headers()
        .get(key)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_string()
}

fn get_query_param(querystring: &str, key: &str) -> String {
    let hash_query: HashMap<String, String> =
        Url::parse(&format!("https://whatever{}", querystring))
            .unwrap()
            .query_pairs()
            .into_owned()
            .collect();
    hash_query.get(key).unwrap_or(&"".to_string()).to_owned()
}

fn get_cookie(req: &Request, key: &str) -> String {
    req.cookie(key)
        .map(|cookie| cookie.value().to_string())
        .unwrap_or_else(|| "".to_string())
}

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

        let provider_metadata = CoreProviderMetadata::discover(
            &IssuerUrl::new(issuer_url.to_string()).expect("Invalid issuer URL"),
            http_client,
        )
        .unwrap();

        let jwks: JwkSet = reqwest::blocking::Client::builder()
            .use_rustls_tls()
            .build()
            .unwrap()
            .get(&provider_metadata.jwks_uri().url().to_string())
            .send()
            .unwrap()
            .json()
            .unwrap();

        providers.insert(
            hostname.to_lowercase(),
            OIDCProvider {
                client_id: ClientId::new(client_id),
                client_secret: ClientSecret::new(client_secret),
                issuer_url: IssuerUrl::new(issuer_url.to_string()).expect("Invalid issuer URL"),
                scopes: scopes.split(',').map(String::from).collect(),
                jwks,
            },
        );
    }

    providers
}

fn get_oidc_provider_for_hostname(hostname: String) -> Option<OIDCProvider> {
    PROVIDERS.get(&hostname.to_lowercase()).cloned()
}

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
        .add_scopes(
            oidc_provider
                .scopes
                .iter()
                .map(|s| Scope::new(s.to_string())),
        )
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

#[handler]
async fn ok_handler(res: &mut Response) {
    res.status_code(StatusCode::OK).render(Text::Plain("OK"));
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

fn check_cookie(req: &mut Request, _state: &mut PathState) -> bool {
    let hostname = get_header(req, "x-forwarded-host");
    let cookie_name = get_env("FORWARD_AUTH_COOKIE", Some("x_forward_auth_session"));
    let token = get_cookie(req, &cookie_name);

    if token.is_empty() {
        return false;
    }

    let oidc_provider = match get_oidc_provider_for_hostname(hostname.clone()) {
        Some(val) => val,
        None => return false,
    };

    let header = match decode_header(&token) {
        Ok(val) => val,
        Err(_) => {
            return false;
        }
    };

    let key_id = header.kid.unwrap();

    let jwks: JwkSet = oidc_provider.jwks;
    let jwk: &jsonwebtoken::jwk::Jwk = jwks
        .keys
        .iter()
        .find(|k| {
            k.common
                .key_id
                .clone()
                .is_some_and(|s| s.eq(key_id.as_str()))
        })
        .unwrap();

    let key = DecodingKey::from_jwk(&jwk).unwrap();
    let mut validation = Validation::new(header.alg);

    let audience = vec![oidc_provider.client_id.as_str()];
    let issuer = vec![oidc_provider.issuer_url.as_str()];

    validation.set_audience(&audience);
    validation.set_issuer(&issuer);

    let token = decode::<Claims>(&token, &key, &validation);

    token.is_ok()
}

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

    get_oidc_provider_for_hostname(hostname.clone()).is_some()
}

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

    let cookie_name = get_env("FORWARD_AUTH_COOKIE", Some("x_forward_auth_session"));
    res.add_cookie(
        Cookie::build((cookie_name, id_token))
            .secure(proto == "https")
            .build(),
    );
    res.remove_cookie("csrf_state");
    res.remove_cookie("pkce_verifier");

    res.render(Redirect::temporary(format!("{}://{}/", proto, hostname)));
}

#[tokio::main]
async fn main() {
    let router = Router::new()
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

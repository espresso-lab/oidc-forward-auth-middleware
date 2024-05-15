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
use salvo::http::header::{
    REFERRER_POLICY, STRICT_TRANSPORT_SECURITY, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
    X_XSS_PROTECTION,
};
use salvo::http::{HeaderValue, StatusCode};
use salvo::logging::Logger;
use salvo::prelude::{handler, Redirect, Request, Response, Router, Server, TcpListener, Text};
use salvo::routing::PathState;
use salvo::{Listener, Service};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

static PROVIDERS: Lazy<HashMap<String, OIDCProvider>> = Lazy::new(|| get_oidc_providers());

#[derive(Clone, Debug)]
struct OIDCProvider {
    client_id: ClientId,
    client_secret: ClientSecret,
    issuer_url: IssuerUrl,
    scopes: Vec<String>,
    jwks: JwkSet,
    audience: Vec<String>,
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

    info!("Starting to initialize OIDC providers.");

    for i in 0u32.. {
        let hostname = get_env(&format!("OIDC_PROVIDER_{}_HOSTNAME", i), None);
        let issuer_url = get_env(&format!("OIDC_PROVIDER_{}_ISSUER_URL", i), None);
        let client_id = get_env(&format!("OIDC_PROVIDER_{}_CLIENT_ID", i), None);
        let client_secret = get_env(&format!("OIDC_PROVIDER_{}_CLIENT_SECRET", i), None);
        let scopes = get_env(&format!("OIDC_PROVIDER_{}_SCOPES", i), None);
        let audience = get_env(&format!("OIDC_PROVIDER_{}_AUDIENCE", i), None);

        if hostname.is_empty()
            || issuer_url.is_empty()
            || client_id.is_empty()
            || client_secret.is_empty()
            || audience.is_empty()
        {
            debug!("OIDC provider Init: Environment variable set with counter {} is incomplete. Stopping here.", i);
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

        let oidc_provider = OIDCProvider {
            client_id: ClientId::new(client_id),
            client_secret: ClientSecret::new(client_secret),
            issuer_url: IssuerUrl::new(issuer_url.to_string()).expect("Invalid issuer URL"),
            scopes: scopes.split(',').map(String::from).collect(),
            audience: audience.split(',').map(String::from).collect(),
            jwks,
        };

        debug!("OIDC provider details: {:?}", oidc_provider.clone());

        providers.insert(hostname.to_lowercase(), oidc_provider);

        info!(
            "Added OIDC provider: {} -> {}",
            hostname.to_lowercase(),
            issuer_url.to_string()
        );
    }

    if providers.len() == 0 {
        warn!("No OIDC providers initialized. Please check environment variables.")
    } else {
        info!("Initialized {} OIDC provider.", providers.len());
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
            debug!("Request: No OIDC provider known for {}.", hostname.clone());

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
            .http_only(true)
            .build(),
    );
    res.add_cookie(
        Cookie::build(("csrf_state", csrf_state.secret().to_string()))
            .secure(proto == "https")
            .http_only(true)
            .build(),
    );

    debug!("Redirecting client to {}", authorize_url.to_string());

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
        debug!("Cookie key {} is empty.", cookie_name);
        return false;
    }

    debug!("Received cookie value: {}", token.clone());

    let oidc_provider = match get_oidc_provider_for_hostname(hostname.clone()) {
        Some(val) => val,
        None => {
            debug!("OIDC provider not found for hostname {}.", hostname.clone());
            return false;
        }
    };

    let header = match decode_header(&token) {
        Ok(val) => val,
        Err(_) => {
            debug!("Error when decoding headers of token: {}", token.clone());
            return false;
        }
    };

    let key_id = header.kid.unwrap();
    debug!("Token JWK Key ID: {}", key_id.clone());

    let jwks: JwkSet = oidc_provider.jwks;
    let jwk: &jsonwebtoken::jwk::Jwk = match jwks.keys.iter().find(|k| {
        k.common
            .key_id
            .clone()
            .is_some_and(|s| s.eq(key_id.as_str()))
    }) {
        Some(val) => val,
        _ => return false,
    };

    let key = DecodingKey::from_jwk(&jwk).unwrap();
    let mut validation = Validation::new(header.alg);

    validation.set_audience(&oidc_provider.audience);
    validation.set_issuer(&vec![oidc_provider.issuer_url.as_str()]);

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
            .http_only(true)
            .build(),
    );
    res.remove_cookie("csrf_state");
    res.remove_cookie("pkce_verifier");

    res.render(Redirect::temporary(format!("{}://{}/", proto, hostname)));
}

#[handler]
async fn apply_security_headers(req: &mut Request, res: &mut Response) {
    res.headers_mut()
        .insert(X_FRAME_OPTIONS, HeaderValue::from_static("SAMEORIGIN"));

    res.headers_mut().insert(
        STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=63072000; includeSubDomains"),
    );
    res.headers_mut()
        .insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("noopen"));

    res.headers_mut()
        .insert(X_XSS_PROTECTION, HeaderValue::from_static("1; mode=block"));

    res.headers_mut().insert(
        REFERRER_POLICY,
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );

    if get_header(req, "x-forwarded-proto").eq("http") {
        debug!("Redirecting client to HTTPS.");

        res.render(Redirect::temporary(format!(
            "https://{}/{}",
            get_header(req, "x-forwarded-host"),
            get_header(req, "x-forwarded-uri")
        )));
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let enhanced_security_enabled: bool = match env::var("DISABLE_ENHANCED_SECURITY") {
        Ok(val) => {
            if val.to_lowercase().eq("true") || val.eq("1") {
                info!("Enhanced security is disabled.");
                false
            } else {
                info!("Enhanced security is enabled.");
                true
            }
        }
        Err(_) => {
            info!("Enhanced security is enabled.");
            true
        }
    };

    let router = Router::new()
        .hoop_when(apply_security_headers, move |_, _| -> bool {
            enhanced_security_enabled.to_owned()
        })
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

    let service = Service::new(router).hoop(Logger::new());
    let acceptor = TcpListener::new("0.0.0.0:3000").bind().await;

    Server::new(acceptor).serve(service).await;
}

mod oidc_providers;

use std::collections::HashMap;
use std::env;
use std::str::from_utf8;

use base64::prelude::*;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{decode as jwt_decode, decode_header, DecodingKey, Validation};
use oidc_providers::OIDCProviders;
use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType};
use openidconnect::reqwest::http_client;
use openidconnect::url::Url;
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, CsrfToken, Nonce, OAuth2TokenResponse,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RefreshToken, Scope,
};
extern crate base64;
use salvo::http::cookie::time::OffsetDateTime;
use salvo::http::cookie::Cookie;
use salvo::http::header::{
    REFERRER_POLICY, STRICT_TRANSPORT_SECURITY, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
    X_XSS_PROTECTION,
};
use salvo::http::{HeaderValue, StatusCode};
use salvo::logging::Logger;
use salvo::prelude::{
    handler, Depot, Redirect, Request, Response, Router, Server, TcpListener, Text,
};
use salvo::routing::PathState;
use salvo::{Listener, Service};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::OnceLock;
use tracing::{debug, info, warn};
use urlencoding::decode;

static PROVIDERS: OnceLock<OIDCProviders> = OnceLock::new();
static ACCESS_TOKEN_COOKIE_NAME: &str = "x_oidc_access_token";
static REFRESH_TOKEN_COOKIE_NAME: &str = "x_oidc_refresh_token";
static STATE_COOKIE_NAME: &str = "x_oidc_csrf";
static PKCS_COOKIE_NAME: &str = "x_oidc_pkce";

#[derive(Clone, Debug)]
struct ForwardAuthHeaders {
    https: bool,
    protocol: String,
    host: String,
    uri: String,
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

#[handler]
async fn forward_auth_handler(_req: &mut Request, res: &mut Response, depot: &mut Depot) {
    let client = depot.obtain::<CoreClient>().unwrap();
    let scopes = depot.obtain::<Vec<Scope>>().unwrap().to_owned();
    let headers = depot.obtain::<ForwardAuthHeaders>().unwrap();
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (authorize_url, csrf_state, _nonce) = client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scopes(scopes)
        .set_pkce_challenge(pkce_challenge)
        .url();

    res.add_cookie(
        Cookie::build((PKCS_COOKIE_NAME, pkce_verifier.secret().to_string()))
            .secure(headers.https)
            .http_only(true)
            .build(),
    );
    res.add_cookie(
        Cookie::build((STATE_COOKIE_NAME, csrf_state.secret().to_string()))
            .secure(headers.https)
            .http_only(true)
            .build(),
    );

    debug!("Redirecting client to {}", authorize_url.to_string());

    res.render(Redirect::temporary(authorize_url.to_string()));
}

#[handler]
async fn status_handler(res: &mut Response) {
    res.status_code(StatusCode::NO_CONTENT);
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

#[handler]
async fn ok_handler(req: &mut Request, res: &mut Response) {
    let headers = res.headers_mut();
    let sub_header = req.headers().get("X-Forwarded-User");

    // Depot would be better, but check_cookie middleware does not support it
    // TODO: Fix with actix migration

    if sub_header.is_some() {
        debug!(
            "X-Forwarded-User: {}",
            &sub_header.clone().unwrap().to_str().unwrap()
        );

        headers.insert("X-Forwarded-User", sub_header.unwrap().to_owned());
    }

    res.status_code(StatusCode::NO_CONTENT);
}

fn get_jwt_expiry(token: &str) -> Result<OffsetDateTime, &str> {
    let jwt_json = token
        .split(".")
        .nth(1)
        .map(|s| BASE64_STANDARD.decode(s).unwrap())
        .map(|bytes| from_utf8(&bytes).unwrap().to_owned());

    if jwt_json.is_none() {
        return Err("jwt json is none.");
    }

    let v: Value = serde_json::from_str(&jwt_json.unwrap()).unwrap();

    if !v["exp"].is_number() {
        return Err("No expiry set.");
    }

    let expiration_timestamp = v["exp"].as_i64().unwrap();

    return Ok(OffsetDateTime::from_unix_timestamp(expiration_timestamp).unwrap());
}

fn has_refresh_token(req: &mut Request, _state: &mut PathState) -> bool {
    let refresh_token = get_cookie(req, REFRESH_TOKEN_COOKIE_NAME);

    !refresh_token.is_empty()
}

#[handler]
async fn renew_access_token(req: &mut Request, res: &mut Response, depot: &mut Depot) {
    let refresh_token = decode(&get_cookie(req, REFRESH_TOKEN_COOKIE_NAME))
        .unwrap()
        .to_string();

    let client = depot.obtain::<CoreClient>().unwrap();
    let headers = depot.obtain::<ForwardAuthHeaders>().unwrap();
    let scopes = depot.obtain::<Vec<Scope>>().unwrap().to_owned();

    let token_response = match client
        .exchange_refresh_token(&RefreshToken::new(refresh_token.to_owned()))
        .add_scopes(scopes) // TODO: Test if required
        .request(http_client)
    {
        Ok(v) => v,
        Err(err) => {
            debug!("Refresh token: {}", &refresh_token);
            warn!("Error exchanging refresh token: {}", err);

            // If the token is invalid, remove the cookie and try again.
            // TODO: Directly redirect to forward_auth_handler
            res.remove_cookie(REFRESH_TOKEN_COOKIE_NAME);
            res.render(Redirect::temporary(format!(
                "{}://{}/{}",
                headers.protocol,
                headers.host,
                headers.uri.trim_start_matches("/")
            )));

            return;
        }
    };

    let access_token = decode(&token_response.access_token().secret())
        .unwrap()
        .into_owned();

    let refresh_token = decode(&token_response.refresh_token().unwrap().secret())
        .unwrap()
        .into_owned();

    if access_token.is_empty() {
        res.status_code(StatusCode::UNAUTHORIZED);
    }

    res.add_cookie(
        Cookie::build((ACCESS_TOKEN_COOKIE_NAME, access_token.to_owned()))
            .secure(headers.https)
            .http_only(true)
            .expires(get_jwt_expiry(&access_token.as_str()).unwrap())
            .build(),
    );

    res.add_cookie(
        Cookie::build((REFRESH_TOKEN_COOKIE_NAME, refresh_token))
            .secure(headers.https)
            .http_only(true)
            .build(),
    );

    res.render(Redirect::temporary(format!(
        "{}://{}/{}",
        &headers.protocol,
        &headers.host,
        &headers.uri.trim_start_matches("/")
    )));
}

// TODO: Refactor from path check to middleware
fn check_cookie(req: &mut Request, _state: &mut PathState) -> bool {
    let hostname = get_header(req, "x-forwarded-host");
    let token = get_cookie(req, ACCESS_TOKEN_COOKIE_NAME);

    if token.is_empty() {
        debug!("Cookie key {} is empty.", ACCESS_TOKEN_COOKIE_NAME);
        return false;
    }

    debug!("Received cookie value: {}", &token);

    let oidc_provider = match PROVIDERS.get().unwrap().find_by_hostname(&hostname) {
        Some(val) => val,
        None => {
            debug!("OIDC provider not found for hostname {}.", &hostname);
            return false;
        }
    };

    let header = match decode_header(&token) {
        Ok(val) => val,
        Err(_) => {
            debug!("Error when decoding headers of token: {}", &token);
            return false;
        }
    };

    let key_id = header.kid.unwrap();
    debug!("Token JWK Key ID: {}", &key_id);

    let jwks: JwkSet = oidc_provider.clone().jwks;
    let jwk: &jsonwebtoken::jwk::Jwk = match jwks.keys.iter().find(|k| {
        k.common
            .key_id
            .as_ref()
            .is_some_and(|s| s.eq(key_id.as_str()))
    }) {
        Some(val) => val,
        _ => return false,
    };

    let key = DecodingKey::from_jwk(&jwk).unwrap();
    let mut validation = Validation::new(header.alg);

    validation.set_audience(&oidc_provider.audience.clone());
    validation.set_issuer(&vec![oidc_provider.issuer_url.clone().as_str()]);

    let claims = jwt_decode::<Claims>(&token, &key, &validation);

    if !claims.is_ok() {
        return false;
    }

    let sub = claims.unwrap().claims.sub;

    // Does not work in PathFilter :/
    // depot.inject::<Claims>(myclaims);

    // So we pass it via the request header
    let headers = req.headers_mut();
    headers.insert("X-Forwarded-User", HeaderValue::from_str(&sub).unwrap());

    return true;
}

fn check_params(req: &mut Request, _state: &mut PathState) -> bool {
    let uri = get_header(req, "x-forwarded-uri");
    let csrf_state = get_cookie(req, STATE_COOKIE_NAME);
    let code = get_query_param(&uri, "code");
    let state = get_query_param(&uri, "state");

    return !(uri.is_empty()
        || code.is_empty()
        || state.is_empty()
        || csrf_state.is_empty()
        || state != csrf_state);
}

#[handler]
async fn set_cookie(req: &mut Request, res: &mut Response, depot: &mut Depot) {
    let client = depot.obtain::<CoreClient>().unwrap();
    let headers = depot.obtain::<ForwardAuthHeaders>().unwrap();

    let code = get_query_param(&headers.uri, "code");
    let pkce_verifier = get_cookie(req, PKCS_COOKIE_NAME);

    if code.is_empty() {
        return res
            .status_code(StatusCode::BAD_GATEWAY)
            .render(Text::Plain("No Token in response."));
    }

    let token_response = client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier))
        .request(http_client)
        .unwrap();

    let access_token = token_response.access_token().secret().to_owned();
    let refresh_token = token_response.refresh_token().unwrap().secret().to_owned();

    res.add_cookie(
        Cookie::build((ACCESS_TOKEN_COOKIE_NAME, access_token))
            .secure(headers.https)
            .http_only(true)
            .build(),
    );

    res.add_cookie(
        Cookie::build((REFRESH_TOKEN_COOKIE_NAME, refresh_token))
            .secure(headers.https)
            .http_only(true)
            .build(),
    );

    res.remove_cookie(STATE_COOKIE_NAME);
    res.remove_cookie(PKCS_COOKIE_NAME);

    // Todo: redirect to the page vistited before
    res.render(Redirect::temporary(format!(
        "{}://{}/",
        headers.protocol, headers.host
    )));
}

#[handler]
async fn apply_security_headers(_req: &mut Request, res: &mut Response, depot: &mut Depot) {
    let auth_headers = depot.obtain::<ForwardAuthHeaders>().unwrap();
    let headers = res.headers_mut();

    headers.insert(X_FRAME_OPTIONS, HeaderValue::from_static("SAMEORIGIN"));
    headers.insert(
        STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=63072000; includeSubDomains"),
    );
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("noopen"));
    headers.insert(X_XSS_PROTECTION, HeaderValue::from_static("1; mode=block"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));

    if !auth_headers.https {
        debug!("Redirecting client to HTTPS.");

        res.render(Redirect::temporary(format!(
            "https://{}/{}",
            auth_headers.host,
            auth_headers.uri.trim_start_matches("/")
        )));
    }
}

#[handler]
async fn apply_oauth2_client(req: &mut Request, res: &mut Response, depot: &mut Depot) {
    let forward_headers = ForwardAuthHeaders {
        host: get_header(req, "x-forwarded-host"),
        protocol: get_header(req, "x-forwarded-proto").to_owned(),
        https: get_header(req, "x-forwarded-proto")
            .to_lowercase()
            .eq("https"),
        uri: get_header(req, "x-forwarded-uri"),
    };

    let oidc_provider = match PROVIDERS
        .get()
        .unwrap()
        .find_by_hostname(&forward_headers.host)
    {
        Some(val) => val,
        None => {
            return res
                .status_code(StatusCode::INTERNAL_SERVER_ERROR)
                .render(Text::Plain("No OIDC provider found for hostname."));
        }
    };

    let provider_metadata =
        CoreProviderMetadata::discover(&oidc_provider.clone().issuer_url, http_client).unwrap();

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        oidc_provider.client_id.to_owned(),
        Some(oidc_provider.client_secret.to_owned()),
    )
    .set_redirect_uri(
        RedirectUrl::new(
            format!(
                "{}://{}/auth_callback",
                &forward_headers.protocol, &forward_headers.host
            )
            .to_string(),
        )
        .expect("Invalid redirect URL"),
    );

    depot.inject(forward_headers.clone());
    depot.inject(client);
    depot.inject(oidc_provider.scopes.clone());
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    PROVIDERS.get_or_init(|| OIDCProviders::new());

    let enhanced_security_enabled: bool = match env::var("DISABLE_ENHANCED_SECURITY") {
        Ok(val) => !(val.to_lowercase().eq("true") || val.eq("1")),
        Err(_) => true,
    };

    let router = Router::new()
        .push(Router::with_path("/status").get(status_handler))
        .push(
            Router::with_path("/verify")
                .hoop(apply_oauth2_client)
                .then(|router| {
                    if enhanced_security_enabled {
                        info!("Enhanced security is enabled.");
                        router.hoop(apply_security_headers)
                    } else {
                        info!("Enhanced security is disabled.");
                        router
                    }
                })
                .push(Router::with_filter_fn(check_cookie).goal(ok_handler))
                .push(Router::with_filter_fn(has_refresh_token).goal(renew_access_token))
                .push(Router::with_filter_fn(check_params).goal(set_cookie))
                .push(Router::new().goal(forward_auth_handler)),
        );

    let service = Service::new(router).hoop(Logger::new());
    let acceptor = TcpListener::new("0.0.0.0:3000").bind().await;

    Server::new(acceptor).serve(service).await;
}

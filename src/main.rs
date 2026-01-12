mod oidc_providers;
mod salvo_utils;

use std::env;
use std::sync::OnceLock;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{decode as jwt_decode, decode_header, DecodingKey, Validation};
use oidc_providers::{get_http_client, OIDCProviders};
use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType};
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, CsrfToken, EndpointMaybeSet, EndpointNotSet,
    EndpointSet, Nonce, OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl,
    RefreshToken, Scope,
};
use salvo::http::cookie::{Cookie, SameSite, time::{Duration, OffsetDateTime}};
use salvo::http::{HeaderValue, StatusCode};
use salvo::logging::Logger;
use salvo::prelude::{
    handler, Depot, Redirect, Request, Response, Router, Server, TcpListener, Text,
};
use salvo::routing::PathState;
use salvo::{Listener, Service};
use salvo_utils::{get_cookie, get_header, get_query_param, security_middleware};
use serde::{Deserialize, Serialize};
use tracing::info;
use urlencoding::decode;

type ConfiguredCoreClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

static PROVIDERS: OnceLock<OIDCProviders> = OnceLock::new();
static ACCESS_TOKEN_COOKIE_NAME: &str = "x_oidc_access_token";
static REFRESH_TOKEN_COOKIE_NAME: &str = "x_oidc_refresh_token";
static CSRF_COOKIE_PREFIX: &str = "x_oidc_csrf_";
static PKCE_COOKIE_PREFIX: &str = "x_oidc_pkce_";

fn build_csrf_cookie_name(nonce: &str) -> String {
    format!("{}{}", CSRF_COOKIE_PREFIX, &nonce[..6.min(nonce.len())])
}

fn build_pkce_cookie_name(nonce: &str) -> String {
    format!("{}{}", PKCE_COOKIE_PREFIX, &nonce[..6.min(nonce.len())])
}

fn find_csrf_cookie(req: &Request) -> Option<(String, String)> {
    req.cookies()
        .iter()
        .find(|c| c.name().starts_with(CSRF_COOKIE_PREFIX))
        .map(|c| (c.name().to_string(), c.value().to_string()))
}

fn find_pkce_cookie(req: &Request) -> Option<(String, String)> {
    req.cookies()
        .iter()
        .find(|c| c.name().starts_with(PKCE_COOKIE_PREFIX))
        .map(|c| (c.name().to_string(), c.value().to_string()))
}

#[derive(Debug, Serialize, Deserialize)]
struct OAuthState {
    csrf: String,
    redirect_uri: String,
}

impl OAuthState {
    fn encode(&self) -> String {
        let json = serde_json::to_string(self).unwrap_or_default();
        URL_SAFE_NO_PAD.encode(json.as_bytes())
    }

    fn decode(encoded: &str) -> Option<Self> {
        let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
        let json = String::from_utf8(bytes).ok()?;
        serde_json::from_str(&json).ok()
    }

    fn nonce(&self) -> &str {
        &self.csrf[..6.min(self.csrf.len())]
    }
}

fn make_auth_flow_cookie(name: &str, value: &str, https: bool) -> Cookie<'static> {
    Cookie::build((name.to_owned(), value.to_owned()))
        .path("/")
        .secure(https)
        .http_only(true)
        .same_site(SameSite::Lax)
        .expires(OffsetDateTime::now_utc() + Duration::hours(1))
        .build()
}

fn make_token_cookie(name: &str, value: &str, https: bool, expires_in_secs: Option<i64>) -> Cookie<'static> {
    let mut builder = Cookie::build((name.to_owned(), value.to_owned()))
        .path("/")
        .secure(https)
        .http_only(true)
        .same_site(SameSite::Lax);
    
    if let Some(secs) = expires_in_secs {
        builder = builder.expires(OffsetDateTime::now_utc() + Duration::seconds(secs));
    }
    
    builder.build()
}

fn clear_cookie(name: &str) -> Cookie<'static> {
    Cookie::build((name.to_owned(), "".to_owned()))
        .path("/")
        .same_site(SameSite::Lax)
        .expires(OffsetDateTime::now_utc() - Duration::hours(1))
        .build()
}

fn extract_jwt_expiry(token: &str) -> Option<i64> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let payload = URL_SAFE_NO_PAD.decode(parts[1]).ok()?;
    let json: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    let exp = json.get("exp")?.as_i64()?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    Some(exp - now)
}

fn strip_oauth_params(uri: &str) -> String {
    if let Some(query_start) = uri.find('?') {
        let path = &uri[..query_start];
        let query = &uri[query_start + 1..];
        let filtered: Vec<&str> = query
            .split('&')
            .filter(|p| !p.starts_with("code=") && !p.starts_with("state="))
            .collect();
        if filtered.is_empty() {
            path.to_string()
        } else {
            format!("{}?{}", path, filtered.join("&"))
        }
    } else {
        uri.to_string()
    }
}

#[derive(Clone, Debug)]
struct ForwardAuthHeaders {
    https: bool,
    protocol: String,
    host: String,
    uri: String,
}

impl ForwardAuthHeaders {
    fn build_url(&self, path: &str) -> String {
        if path.starts_with('/') {
            format!("{}://{}{}", self.protocol, self.host, path)
        } else {
            format!("{}://{}/{}", self.protocol, self.host, path)
        }
    }
}

fn start_auth_flow(
    client: &ConfiguredCoreClient,
    headers: &ForwardAuthHeaders,
    scopes: Vec<Scope>,
    res: &mut Response,
) {
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let csrf_token = CsrfToken::new_random();

    let original_uri = strip_oauth_params(&headers.uri);
    let oauth_state = OAuthState {
        csrf: csrf_token.secret().clone(),
        redirect_uri: original_uri,
    };

    let (authorize_url, _csrf_state, _nonce) = client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            move || csrf_token.clone(),
            Nonce::new_random,
        )
        .add_scopes(scopes)
        .set_pkce_challenge(pkce_challenge)
        .url();

    let nonce = oauth_state.nonce();
    res.add_cookie(make_auth_flow_cookie(
        &build_pkce_cookie_name(nonce),
        pkce_verifier.secret(),
        headers.https,
    ));
    res.add_cookie(make_auth_flow_cookie(
        &build_csrf_cookie_name(nonce),
        &oauth_state.csrf,
        headers.https,
    ));

    let mut redirect_url = authorize_url.to_string();
    if let Some(pos) = redirect_url.find("&state=") {
        let end_pos = redirect_url[pos + 7..]
            .find('&')
            .map(|p| pos + 7 + p)
            .unwrap_or(redirect_url.len());
        redirect_url = format!(
            "{}&state={}{}",
            &redirect_url[..pos],
            oauth_state.encode(),
            &redirect_url[end_pos..]
        );
    }

    res.render(Redirect::temporary(redirect_url));
}

#[handler]
async fn forward_auth_handler(req: &mut Request, res: &mut Response, depot: &mut Depot) {
    let client = depot.obtain::<ConfiguredCoreClient>().unwrap();
    let scopes = depot.obtain::<Vec<Scope>>().unwrap().to_owned();
    let headers = depot.obtain::<ForwardAuthHeaders>().unwrap();

    let uri = get_header(req, "x-forwarded-uri");
    let code = get_query_param(&uri, "code");
    let state = get_query_param(&uri, "state");

    if !code.is_empty() && !state.is_empty() {
        let redirect_path = OAuthState::decode(&state)
            .map(|s| s.redirect_uri)
            .filter(|uri| !uri.is_empty() && !uri.contains("code="))
            .unwrap_or_else(|| "/".to_string());
        res.render(Redirect::temporary(headers.build_url(&redirect_path)));
        return;
    }

    start_auth_flow(client, headers, scopes, res);
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

    if let Some(sub) = sub_header {
        headers.insert("X-Forwarded-User", sub.to_owned());
    }

    res.status_code(StatusCode::NO_CONTENT);
}

fn has_refresh_token(req: &mut Request, _state: &mut PathState) -> bool {
    let refresh_token = get_cookie(req, REFRESH_TOKEN_COOKIE_NAME);
    !refresh_token.is_empty()
}

#[handler]
async fn renew_access_token(req: &mut Request, res: &mut Response, depot: &mut Depot) {
    let refresh_token = match decode(&get_cookie(req, REFRESH_TOKEN_COOKIE_NAME)) {
        Ok(v) => v.to_string(),
        Err(_) => {
            res.status_code(StatusCode::UNAUTHORIZED);
            return;
        }
    };

    let client = depot.obtain::<ConfiguredCoreClient>().unwrap();
    let headers = depot.obtain::<ForwardAuthHeaders>().unwrap();
    let scopes = depot.obtain::<Vec<Scope>>().unwrap().to_owned();

    let token_response = match client
        .exchange_refresh_token(&RefreshToken::new(refresh_token.to_owned()))
        .unwrap()
        .add_scopes(scopes.clone())
        .request_async(get_http_client())
        .await
    {
        Ok(v) => v,
        Err(_) => {
            res.add_cookie(clear_cookie(ACCESS_TOKEN_COOKIE_NAME));
            res.add_cookie(clear_cookie(REFRESH_TOKEN_COOKIE_NAME));
            start_auth_flow(client, headers, scopes, res);
            return;
        }
    };

    let access_token = match decode(token_response.access_token().secret()) {
        Ok(v) => v.into_owned(),
        Err(_) => {
            res.status_code(StatusCode::UNAUTHORIZED);
            return;
        }
    };

    let refresh_token = match token_response.refresh_token() {
        Some(rt) => match decode(rt.secret()) {
            Ok(v) => v.into_owned(),
            Err(_) => {
                res.status_code(StatusCode::UNAUTHORIZED);
                return;
            }
        },
        None => {
            res.status_code(StatusCode::UNAUTHORIZED);
            return;
        }
    };

    if access_token.is_empty() {
        res.status_code(StatusCode::UNAUTHORIZED);
        return;
    }

    let access_expiry = extract_jwt_expiry(&access_token);
    res.add_cookie(make_token_cookie(ACCESS_TOKEN_COOKIE_NAME, &access_token, headers.https, access_expiry));
    res.add_cookie(make_token_cookie(REFRESH_TOKEN_COOKIE_NAME, &refresh_token, headers.https, None));

    let clean_uri = strip_oauth_params(&headers.uri);
    res.render(Redirect::temporary(headers.build_url(&clean_uri)));
}

fn check_cookie(req: &mut Request, _state: &mut PathState) -> bool {
    let hostname = get_header(req, "x-forwarded-host");
    let token = get_cookie(req, ACCESS_TOKEN_COOKIE_NAME);

    if token.is_empty() {
        return false;
    }

    let oidc_provider = match PROVIDERS.get().unwrap().find_by_hostname(&hostname) {
        Some(val) => val,
        None => return false,
    };

    let header = match decode_header(&token) {
        Ok(val) => val,
        Err(_) => return false,
    };

    let key_id = match header.kid {
        Some(kid) => kid,
        None => return false,
    };

    let jwk = match oidc_provider.jwks.keys.iter().find(|k| {
        k.common.key_id.as_ref().is_some_and(|s| s == &key_id)
    }) {
        Some(val) => val,
        _ => return false,
    };

    let key = match DecodingKey::from_jwk(jwk) {
        Ok(k) => k,
        Err(_) => return false,
    };

    let mut validation = Validation::new(header.alg);
    validation.set_audience(&oidc_provider.audience);
    validation.set_issuer(&[oidc_provider.issuer_url.as_str()]);

    let claims = match jwt_decode::<Claims>(&token, &key, &validation) {
        Ok(c) => c,
        Err(_) => return false,
    };

    let sub = claims.claims.sub;
    let headers = req.headers_mut();
    headers.insert("X-Forwarded-User", HeaderValue::from_str(&sub).unwrap());

    true
}

fn check_params(req: &mut Request, _state: &mut PathState) -> bool {
    let uri = get_header(req, "x-forwarded-uri");
    let code = get_query_param(&uri, "code");
    let state = get_query_param(&uri, "state");

    if uri.is_empty() || code.is_empty() || state.is_empty() {
        return false;
    }

    let oauth_state = match OAuthState::decode(&state) {
        Some(s) => s,
        None => return false,
    };

    let csrf_cookie = match find_csrf_cookie(req) {
        Some((_, value)) => value,
        None => return false,
    };

    oauth_state.csrf == csrf_cookie
}

#[handler]
async fn set_cookie(req: &mut Request, res: &mut Response, depot: &mut Depot) {
    let client = depot.obtain::<ConfiguredCoreClient>().unwrap();
    let headers = depot.obtain::<ForwardAuthHeaders>().unwrap();

    let code = get_query_param(&headers.uri, "code");
    let state = get_query_param(&headers.uri, "state");

    let redirect_to_clean_url = || headers.build_url(&strip_oauth_params(&headers.uri));

    let (pkce_cookie_name, pkce_verifier) = match find_pkce_cookie(req) {
        Some((name, value)) => (name, value),
        None => {
            res.render(Redirect::temporary(redirect_to_clean_url()));
            return;
        }
    };

    let csrf_cookie_name = match find_csrf_cookie(req) {
        Some((name, _)) => name,
        None => String::new(),
    };

    if code.is_empty() {
        res.render(Redirect::temporary(redirect_to_clean_url()));
        return;
    }

    let token_response = match client
        .exchange_code(AuthorizationCode::new(code))
        .unwrap()
        .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier))
        .request_async(get_http_client())
        .await
    {
        Ok(tr) => tr,
        Err(_) => {
            res.add_cookie(clear_cookie(&pkce_cookie_name));
            if !csrf_cookie_name.is_empty() {
                res.add_cookie(clear_cookie(&csrf_cookie_name));
            }
            res.render(Redirect::temporary(redirect_to_clean_url()));
            return;
        }
    };

    let access_token = token_response.access_token().secret().to_owned();
    let refresh_token = match token_response.refresh_token() {
        Some(rt) => rt.secret().to_owned(),
        None => String::new(),
    };

    let access_expiry = extract_jwt_expiry(&access_token);
    res.add_cookie(make_token_cookie(ACCESS_TOKEN_COOKIE_NAME, &access_token, headers.https, access_expiry));

    if !refresh_token.is_empty() {
        res.add_cookie(make_token_cookie(REFRESH_TOKEN_COOKIE_NAME, &refresh_token, headers.https, None));
    }

    res.add_cookie(clear_cookie(&pkce_cookie_name));
    if !csrf_cookie_name.is_empty() {
        res.add_cookie(clear_cookie(&csrf_cookie_name));
    }

    let redirect_path = OAuthState::decode(&state)
        .map(|s| s.redirect_uri)
        .filter(|uri| !uri.is_empty() && !uri.contains("code="))
        .unwrap_or_else(|| "/".to_string());

    res.render(Redirect::temporary(headers.build_url(&redirect_path)));
}

#[handler]
async fn apply_oauth2_client(req: &mut Request, res: &mut Response, depot: &mut Depot) {
    let protocol = get_header(req, "x-forwarded-proto");
    let forward_headers = ForwardAuthHeaders {
        host: get_header(req, "x-forwarded-host"),
        https: protocol.eq_ignore_ascii_case("https"),
        protocol,
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
        CoreProviderMetadata::discover_async(oidc_provider.issuer_url.clone(), get_http_client())
            .await
            .unwrap();

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        oidc_provider.client_id.clone(),
        Some(oidc_provider.client_secret.clone()),
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

    let enhanced_security_enabled = match env::var("DISABLE_ENHANCED_SECURITY") {
        Ok(val) => !(val.to_lowercase().eq("true") || val.eq("1")),
        Err(_) => true,
    };

    let oidc_providers = OIDCProviders::new().await;
    PROVIDERS.get_or_init(move || oidc_providers);

    let router = Router::new()
        .push(Router::with_path("/status").goal(status_handler))
        .push(
            Router::with_path("/verify")
                .hoop(apply_oauth2_client)
                .then(|router| {
                    if enhanced_security_enabled {
                        info!("Enhanced security is enabled.");
                        router.hoop(security_middleware)
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

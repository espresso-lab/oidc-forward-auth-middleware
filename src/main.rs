use cookie::Cookie;
use openidconnect::core::{
    CoreClient, CoreIdTokenClaims, CoreIdTokenVerifier, CoreProviderMetadata, CoreResponseType,
};
use openidconnect::reqwest::http_client;
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    OAuth2TokenResponse, RedirectUrl, Scope,
};
use salvo::http::StatusCode;
use salvo::prelude::*;
use std::env;

fn get_env(key: &str, default: Option<&str>) -> String {
    env::var(key).unwrap_or_else(|_| default.unwrap_or("").to_owned())
}

// Implement this:
// https://github.com/ramosbugs/openidconnect-rs/blob/main/examples/gitlab.rs

// Examples: https://github.com/salvo-rs/salvo/blob/main/examples/csrf-cookie-store/src/main.rs

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

fn get_oidc_providers() -> Vec<OIDCProvider> {
    let binding = get_env("AUTH_HOSTNAMES", None);
    let hostnames = binding.split(",").collect::<Vec<_>>();
    let binding = get_env("AUTH_PROVIDER_URLS", None);
    let urls = binding.split(",").collect::<Vec<_>>();
    let binding = get_env("AUTH_CLIENT_IDS", None);
    let clients = binding.split(",").collect::<Vec<_>>();
    let binding = get_env("AUTH_SECRETS", None);
    let secrets = binding.split(",").collect::<Vec<_>>();

    urls.iter()
        .enumerate()
        .map(|(index, url)| OIDCProvider {
            hostname: hostnames.get(index).unwrap().to_string(), // TODO: to lowercase
            client_id: ClientId::new(clients.get(index).unwrap().to_string()),
            client_secret: ClientSecret::new(secrets.get(index).unwrap().to_string()),
            issuer_url: IssuerUrl::new(url.to_string()).expect("Invalid issuer URL"),
        })
        .collect()
}

// TODO: Get the credentials from the provided hostname
fn get_oidc_provider_for_hostname(hostname: String) -> Option<OIDCProvider> {
    get_oidc_providers()
        .iter()
        .find(|provider| provider.hostname == hostname)
        .cloned()
}

fn get_auth_cookie(cookie_string: &str) -> String {
    let mut cookie_value = None;
    for cookie in Cookie::split_parse(cookie_string) {
        let cookie = cookie.unwrap();

        if cookie.name() == get_env("AUTH_COOKIE_NAME", Some("forward_auth")) {
            cookie_value = Some(cookie.value().to_string());
            break;
        }
    }
    cookie_value.unwrap_or_default()
}

#[handler]
async fn forward_auth_handler(req: &mut Request, res: &mut Response) {
    // TODO: to lowercase
    let hostname = req
        .headers()
        .get("X-Forwarded-Host")
        .expect("X-Forwarded-Host needed")
        .to_str()
        .unwrap_or("")
        .to_string();

    // Get the OIDC Provider
    let oidc_provider = match get_oidc_provider_for_hostname(hostname.clone()) {
        Some(val) => val,
        None => {
            return res
                .status_code(StatusCode::BAD_GATEWAY)
                .render(Text::Plain("No OIDC provider known for hostname."))
        }
    };
    let issuer_url = oidc_provider.issuer_url.url().to_string();
    let client_id = oidc_provider.client_id.to_string();

    // Load this on start and NOT per request
    let provider_metadata = tokio::task::spawn_blocking(move || {
        let my_issuer_url = IssuerUrl::new(issuer_url).expect("Invalid issuer URL");

        CoreProviderMetadata::discover(&my_issuer_url, http_client).unwrap_or_else(|err| {
            handle_error(&err, "Failed to discover OpenID Provider");
            unreachable!();
        })
    })
    .await
    .unwrap();

    let hostname2 = hostname.clone();

    // Set up the config for the GitLab OAuth2 process.
    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        oidc_provider.client_id,
        Some(oidc_provider.client_secret),
    )
    .set_redirect_uri(
        RedirectUrl::new(format!("https://{}/auth_callback", hostname2).to_string())
            .expect("Invalid redirect URL"),
    );

    println!("4 Hallo Welt");

    // Generate the authorization URL to which we'll redirect the user.
    let (authorize_url, csrf_state, nonce) = client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .url();

    println!("Open this URL in your browser:\n{}\n", authorize_url);

    // TODO: csrf_state und nonce wegspeichern

    // https://example.com/oauth_callback?state=eyJzdGF0ZSI6IlYxZFFUa0pYTUVjMFJVVTFNVmhNVURFek1VRlVWVE5RUnpwaVJWbHJVelpFVmxSTFJuZzVSV05LV0dsSlRscFNSRWRYWTNCS1REbExRbUZqTlVOalExZE5ZME56UFE9PSIsImlkcF9uYW1lIjoia2FuaWRtIn0%3D&code=gAAAAABmBzT5hPIYqxegNadrOyAUX3Wldm_ECT_OCztlX3PKJZ5OBKLPI5cPxgaDKhR9ci7DBvGHz6uWVWFXBeSysDL215eEpPNHFbS9-MGat9HjSRfwjeStdoEp46Y3YZ-i_GyszW1EhUgMO4S5uyRG8zty1JKnREqtAldhlcNqCdxXSZZw-4d7quAr_bPaywON1I6lEur7RMthEdM4Sf1_h_khWb08N-KFyWeVV50myHqHAAuBuxvDte416XTMod7VCabkq9iI6TGmYzTFHQwI6r7m-oBoh_zP90_E9vH9V-JxY8JqSkW1FLiMGaKDz1C_MAhPI3MwrBt-_lf1ncte0Z3UAn3I3w07BmMe2h3CWrz7IzV8kZ2D_vrAvlBezo_P9EgUCxvuP8KVYTGhULo6sNHGAMirfQ%3D%3D

    let str_code = req.query::<String>("code");
    let str_state = req.query::<String>("state");

    // Verify stuff
    if !str_code.is_none() && !str_state.is_none() {
        let code = AuthorizationCode::new(str_code.unwrap());
        let state = CsrfToken::new(str_state.unwrap());

        println!("GitLab returned the following code:\n{}\n", code.secret());
        println!(
            "GitLab returned the following state:\n{} (expected `{}`)\n",
            state.secret(),
            csrf_state.secret()
        );

        // Exchange the code with a token.
        let token_response = client
            .exchange_code(code)
            .request(http_client)
            .unwrap_or_else(|err| {
                handle_error(&err, "Failed to contact token endpoint");
                unreachable!();
            });

        println!(
            "GitLab returned access token:\n{}\n",
            token_response.access_token().secret()
        );
        println!("GitLab returned scopes: {:?}", token_response.scopes());

        let id_token_verifier: CoreIdTokenVerifier = client.id_token_verifier();
        let id_token_claims: &CoreIdTokenClaims = token_response
            .extra_fields()
            .id_token()
            .expect("Server did not return an ID token")
            .claims(&id_token_verifier, &nonce)
            .unwrap_or_else(|err| {
                handle_error(&err, "Failed to verify ID token");
                unreachable!();
            });
        println!("GitLab returned ID token: {:?}\n", id_token_claims);

        res.status_code(StatusCode::OK).render(Text::Plain("OK"));
    }

    res.render(Redirect::temporary(authorize_url.to_string()));

    ////////////////////////////////
    // HEADERS
    // for (key, value) in req.headers().into_iter() {
    //     println!("{}: {}", key.as_str(), value.to_str().unwrap_or_default());
    // }
    ////////////////////////////////

    ////////////////////////////////
    // JWT

    // let jwt_cookie = get_auth_cookie(
    //     req.headers()
    //         .get("cookie")
    //         .expect("")
    //         .to_str()
    //         .unwrap_or_default(),
    // );
    // println!("JWT: {}", jwt_cookie);

    // let headerx = match req.headers().get("X-Forwarded-Host") {
    //     Some(header) => header.to_str().unwrap_or(""),
    //     None => "",
    // };

    // println!("X-Forwarded-Host: {}", headerx);

    // Refactor these lines
    // println!("X-Forwarded-Host: {}", req.headers().get("X-Forwarded-Host").expect("").to_str().unwrap_or(""));
    // println!("X-Forwarded-Proto: {}", req.headers().get("X-Forwarded-Proto").expect("").to_str().unwrap_or(""));
    // println!("X-Forwarded-Uri: {}", req.headers().get("X-Forwarded-Uri").expect("").to_str().unwrap_or(""));
    // println!("X-Forwarded-For: {}", req.headers().get("X-Forwarded-For").expect("").to_str().unwrap_or(""));
    // println!("-------");

    // res.headers_mut().insert(header::SERVER, HeaderValue::from_static("Salvo"));

    ////////////////
    // Response
    // if jwt_cookie == "0" {
    //     res.status_code(StatusCode::UNAUTHORIZED)
    //         .render(Text::Plain("NOK"));
    // } else if jwt_cookie == "1" {
    //     res.status_code(StatusCode::OK).render(Text::Plain("OK"));
    // } else {
    //     res.render(Redirect::temporary(authorize_url.to_string()));
    // }
}

#[handler]
async fn status(res: &mut Response) {
    res.status_code(StatusCode::OK).render(Text::Html("Ok. ✅"));
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();

    let router = Router::new()
        .push(Router::with_path("/status").get(status))
        .push(Router::with_path("/verify").get(forward_auth_handler));

    let acceptor = TcpListener::new("0.0.0.0:3000").bind().await;
    Server::new(acceptor).serve(router).await;
}

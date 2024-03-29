use cookie::Cookie;
use salvo::http::StatusCode;
use salvo::prelude::*;

// Implement this:
// https://github.com/ramosbugs/openidconnect-rs/blob/main/examples/gitlab.rs

// Examples: https://github.com/salvo-rs/salvo/blob/main/examples/csrf-cookie-store/src/main.rs

fn get_auth_cookie(cookie_string: &str) -> String {
    let mut cookie_value = None;
    for cookie in Cookie::split_parse(cookie_string) {
        let cookie = cookie.unwrap();

        if cookie.name() == "traefik_oidc" {
            cookie_value = Some(cookie.value().to_string());
            break;
        }
    }

    cookie_value.unwrap_or_default()
}

#[handler]
async fn forward_auth_handler(req: &mut Request, res: &mut Response, _depot: &mut Depot) {
    // let user = depot.get::<&str>("traefik_oidc").copied().unwrap_or("");
    // println!("JWT: {}", user);

    ////////////////////////////////
    // HEADERS
    for (key, value) in req.headers().into_iter() {
        println!("{}: {}", key.as_str(), value.to_str().unwrap_or_default());
    }
    ////////////////////////////////

    ////////////////////////////////
    // JWT
    let jwt_cookie = get_auth_cookie(
        req.headers()
            .get("cookie")
            .expect("")
            .to_str()
            .unwrap_or_default(),
    );
    println!("JWT: {}", jwt_cookie);

    let headerx = match req.headers().get("X-Forwarded-Host") {
        Some(header) => header.to_str().unwrap_or(""),
        None => "",
    };

    println!("X-Forwarded-Host: {}", headerx);

    // Refactor these lines
    // println!("X-Forwarded-Host: {}", req.headers().get("X-Forwarded-Host").expect("").to_str().unwrap_or(""));
    // println!("X-Forwarded-Proto: {}", req.headers().get("X-Forwarded-Proto").expect("").to_str().unwrap_or(""));
    // println!("X-Forwarded-Uri: {}", req.headers().get("X-Forwarded-Uri").expect("").to_str().unwrap_or(""));
    // println!("X-Forwarded-For: {}", req.headers().get("X-Forwarded-For").expect("").to_str().unwrap_or(""));
    // println!("-------");

    // res.headers_mut().insert(header::SERVER, HeaderValue::from_static("Salvo"));

    ////////////////
    // Response
    if jwt_cookie == "0" {
        res.status_code(StatusCode::UNAUTHORIZED)
            .render(Text::Plain("NOK"));
    } else if jwt_cookie == "1" {
        res.status_code(StatusCode::OK).render(Text::Plain("OK"));
    } else {
        res.render(Redirect::temporary("https://salvo.rs/"));
    }
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

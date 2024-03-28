use salvo::prelude::*;
use salvo::http::StatusCode;
use rand::*;
use cookie::Cookie;

// Examples: https://github.com/salvo-rs/salvo/blob/main/examples/csrf-cookie-store/src/main.rs

fn get_auth_cookie(cookie_string: &str) -> String{

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
async fn authorizer(req: &mut Request, res: &mut Response, _depot: &mut Depot) {
    let mut rng = rand::thread_rng();
    let random = rng.gen_range(0..3);

    // let user = depot.get::<&str>("traefik_oidc").copied().unwrap_or("");
    // println!("JWT: {}", user);

    for (key, value) in req.headers().into_iter() {
        println!("{}: {}", key.as_str(), value.to_str().unwrap_or_default());
    }


    let jwt_cookie = get_auth_cookie(req.headers().get("cookie").expect("").to_str().unwrap_or_default());

    println!("JWT: {}", jwt_cookie);
    
    // X-Forwarded-Host
    // X-Forwarded-Proto
    // X-Forwarded-Uri
    // X-Forwarded-For

    // res.headers_mut()
    // .insert(header::SERVER, HeaderValue::from_static("Salvo"));

    if jwt_cookie == "0" {
        res.status_code(StatusCode::UNAUTHORIZED).render(Text::Plain("NOK"));
    } else if jwt_cookie == "1" {
        res.status_code(StatusCode::OK).render(Text::Plain("OK"));
        
    } else {
        res.render(Redirect::temporary("https://salvo.rs/"));
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();

    let router = Router::with_path("/authorize").get(authorizer);
    let acceptor = TcpListener::new("127.0.0.1:8080").bind().await;
    Server::new(acceptor).serve(router).await;
}

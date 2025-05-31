use axum::Router;
use axum::routing::{get, post};
use crate::presentation::controller::{get_info_handler, login_handler};

mod presentation;
mod domain;
mod application;
mod infrastructure;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/login", post(login_handler))
        .route("/info", get(get_info_handler));

    let listener =
    tokio::net::TcpListener::bind(("127.0.0.1", 8080))
        .await
        .unwrap();

    println!("Listening on {}", listener.local_addr().unwrap());

    axum::serve(listener, app)
        .await
        .unwrap();
}

use std::{env, sync::Arc};
mod routingserver;
mod server;
use routingserver::RoutingServer;
use server::{Request, Response, Server};

fn main() {
    println!("Hello!");
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: {} <run|count|rotate|update_config>", args[0]);
        return;
    }

    let mut http_server = RoutingServer::new();
    http_server.add_route(server::Method::GET, "/status".to_string(), handle_status);
    http_server.add_route(server::Method::GET, "/".to_string(), handle_html);

    match args[1].as_str() {
        "run" => RoutingServer::run(Arc::new(http_server)),
        "count" => println!("Number of lines: {}", RoutingServer::count()),
        "rotate" => RoutingServer::rotate(),
        "update_config" => {
            RoutingServer::update_config(args[2].parse::<u8>().expect("Failed to parse verbosity"))
        }
        _ => {
            println!("Usage: {} <run|count|rotate|update_config>", args[0]);
            return;
        }
    }
}

fn handle_status(request: &Request) -> Response {
    let mut response = Response {
        status: 200,
        body: String::default(),
        response_type: server::ResponseType::Json,
    };
    response.body = format!(
        "{{\"status\": \"OK\",\n\"method\": \"{:?}\",\n\"path\": \"{}\",\n\"timestamp\": \"{}\"}}",
        request.method,
        request.path,
        chrono::Utc::now().to_rfc3339()
    );
    response
}

fn handle_html(_request: &Request) -> Response {
    let mut response = Response {
        status: 200,
        body: String::default(),
        response_type: server::ResponseType::Html,
    };

    response.body = "<html>
            <body>
            <h1>Request received!</h1>
            <body>
            </html>"
        .to_string();
    response
}

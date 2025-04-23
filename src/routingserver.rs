use std::collections::HashMap;
use crate::server::{Method, Request, Response, Server};

pub struct RoutingServer {
  routes: HashMap<(Method, String), fn(&Request) -> Response>,
}

impl RoutingServer {
  pub fn new() -> RoutingServer {
    RoutingServer { routes: HashMap::new() }
  }

  pub fn add_route(&mut self, method: Method, path: String, func: fn(&Request) -> Response) {
    self.routes.insert((method, path), func);
  }
}

impl Server for RoutingServer {
  fn process_request(&self, request: &Request) -> Response {
    let mut response = Response { status: 200, body: String::new(), response_type: crate::server::ResponseType::Text };
    let key = (request.method.clone(), request.path.clone());
    match self.routes.get(&key) {
      Some(route) => return route(request),
      None => {
        response.status = 404;
        return response;
      }
    }
  }
}
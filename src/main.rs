use std::env;
mod server;

fn main() {
    println!("Hello!");
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: {} <run|count|rotate|update_config>", args[0]);
        return;
    }
    match args[1].as_str() {
        "run" => server::run(),
        "count" => println!("Number of lines: {}", server::count()),
        "rotate" => server::rotate(),
        "update_config" => {
            server::update_config(args[2].parse::<u8>().expect("Failed to parse verbosity"))
        }
        _ => {
            println!("Usage: {} <run|count|rotate|update_config>", args[0]);
            return;
        }
    }
}

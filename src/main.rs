//Dependencies
use actix_cors::Cors;
use actix_web::middleware::Logger;
use actix_web::{http::header, web, App, HttpServer};
use config::Config;
use dotenv::dotenv;
use redis::Client;
use ldap3::{LdapConnAsync, Scope, SearchEntry};
use ldap3::result::Result;
use std::collections::HashSet;
use std::sync::Mutex;
use deadpool_ldap::{Manager, Pool};
// Modules 
mod config;
mod user_handler;
mod auth_handler;
mod jwt_auth;
mod user_model;
mod response;
mod token_model;
mod token_service;
mod user_service;
mod ldap_service;
// Types
pub struct AppState {
    env: Config,
    redis_client: Client,
    ldap_pool: Pool,
}
pub struct LdapConnAsyncManager;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "actix_web=info");
    }
    dotenv().ok();
    env_logger::init();
    
    let config = Config::init();

    
    let redis_client = match Client::open(config.redis_url.to_owned()) {
        Ok(client) => {
            println!("✅Connection to the redis is successful!");
            client
        }
        Err(e) => {
            println!("Error connecting to Redis: {}", e);
            std::process::exit(1);
        }
    };

    let manager = Manager::new("ldap://host.docker.internal:389");
    let pool = match Pool::builder(manager).max_size(10).build() {
        Ok(pool) => {
            println!("✅Connection to the LDAP is successful!");
            pool
        }
        Err(e) => {
            println!("Error connecting to LDAP: {}", e);
            std::process::exit(1);
        }
    };
    println!("🚀  Server started successfully ");

    HttpServer::new(move || { 
        let cors = Cors::permissive()
            .allowed_origin("http://0.0.0.0:5000")
            .allowed_methods(vec!["GET", "POST"])
            .allowed_headers(vec![
                header::CONTENT_TYPE,
                header::AUTHORIZATION, 
                header::ACCEPT
                ])
            .supports_credentials();
        App::new()
            .app_data(web::Data::new(AppState {
                env: config.clone(),
                redis_client: redis_client.clone(),
                ldap_pool: pool.clone(),
            }))
            .configure(|cfg| {
                user_handler::config(cfg);
                auth_handler::config(cfg);
            })
            .wrap(cors)
            .wrap(Logger::default())
            
    })
    .bind(("0.0.0.0", 8000))?
    .run()
    .await
}


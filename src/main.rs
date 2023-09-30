//Dependencies
use actix_cors::Cors;
use actix_web::middleware::Logger;
use actix_web::{http::header, web, App, HttpServer};
use config::Config;
use dotenv::dotenv;
use redis::Client;
use sqlx::{postgres::PgPoolOptions, Pool, Postgres, Executor};


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
// Types
pub struct AppState {
    db: Pool<Postgres>,
    env: Config,
    redis_client: Client,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "actix_web=info");
    }
    dotenv().ok();
    env_logger::init();
    
    let config = Config::init();

    let pool = match PgPoolOptions::new()
        .max_connections(10)
        .after_connect(|conn, _meta| Box::pin(async move {   
            conn.execute("DEALLOCATE ALL;")
                .await?;
            Ok(())
        }))
        .connect(&config.database_url)
        .await
    {
        Ok(pool) => {
            println!("✅Connection to pg database is successful!");

            pool
        }
        Err(e) => {
            println!("Failed to connect to Postgres");
            println!("Error: {:?}", e);
            return Ok(());
        }
    };
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

    println!("🚀  Server started successfully ");

    HttpServer::new(move || { 
        let cors = Cors::default()
            .allowed_origin("http://0.0.0.0:3000")
            .allowed_methods(vec!["GET", "POST"])
            .allowed_headers(vec![
                header::CONTENT_TYPE,
                header::AUTHORIZATION, 
                header::ACCEPT
                ])
            .supports_credentials();
        App::new()
            .app_data(web::Data::new(AppState {
                db: pool.clone(),
                env: config.clone(),
                redis_client: redis_client.clone(),
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


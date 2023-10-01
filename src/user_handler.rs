use crate::{
    user_model::{RegisterUserSchema, User},
    user_service::filter_user_record, AppState
};
use actix_web::{
     post, web, HttpResponse, Responder,
};
use argon2::{
    password_hash::{rand_core::OsRng,  PasswordHasher, SaltString},
    Argon2,
};

use sqlx::Row;


#[post("/register")]
async fn register_user_handler(
    body: web::Json<RegisterUserSchema>,
    data: web::Data<AppState>,
) -> impl Responder {
    let exists: bool = sqlx::query("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)")
        .bind(body.email.to_owned())
        .fetch_one(&data.db)
        .await
        .unwrap()
        .get(0);

    if exists {
        return HttpResponse::Conflict().json(
            serde_json::json!({"status": "fail","message": "User with that email already exists"}),
        );
    }

    let salt = SaltString::generate(&mut OsRng);
    let hashed_password = Argon2::default()
        .hash_password(body.password.as_bytes(), &salt)
        .expect("Error while hashing password")
        .to_string();
    let query_result = sqlx::query_as!(
        User,
        "INSERT INTO users (email,password, user_id) VALUES ($1, $2, $3) RETURNING *",
        body.email.to_string().to_lowercase(),
        hashed_password,
        body.user_id
    )
    .fetch_one(&data.db)
    .await;

    match query_result {
        Ok(user) => {
            let user_response = serde_json::json!({"status": "success","data": serde_json::json!({
                "user": filter_user_record(&user)
            })});

            return HttpResponse::Ok().json(user_response);
        }
        Err(e) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "error","message": format!("{:?}", e)}));
        }
    }
}



pub fn config(conf: &mut web::ServiceConfig) {
    let scope = web::scope("/api/user")
        .service(register_user_handler);
    conf.service(scope);
}
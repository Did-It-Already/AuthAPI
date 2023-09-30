use crate::{
    jwt_auth,
    user_model::{LoginUserSchema,  User, RefreshSchema},
    response::filter_user_record,
    token_service, AppState
};
use actix_web::{
    get, post, web, HttpMessage, HttpRequest, HttpResponse, Responder,
};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordVerifier},
    Argon2,
};
use redis::AsyncCommands;
use serde_json::json;




#[post("/login")]
async fn login_user_handler(
    body: web::Json<LoginUserSchema>,
    data: web::Data<AppState>,
) -> impl Responder {
    let query_result = sqlx::query_as!(User, "SELECT * FROM users WHERE email = $1", body.email)
        .fetch_optional(&data.db)
        .await
        .unwrap();

    let user = match query_result {
        Some(user) => user,
        None => {
            return HttpResponse::BadRequest().json(
                serde_json::json!({"status": "fail", "message": "Invalid email or password"}),
            );
        }
    };

    let is_valid = PasswordHash::new(&user.password)
        .and_then(|parsed_hash| {
            Argon2::default().verify_password(body.password.as_bytes(), &parsed_hash)
        })
        .map_or(false, |_| true);

    if !is_valid {
        return HttpResponse::BadRequest()
            .json(json!({"status": "fail", "message": "Invalid email or password"}));
    }


    let access_token_details = match token_service::generate_jwt_token(
        user.id,
        data.env.access_token_max_age,
        data.env.access_token_private_key.to_owned(),
    ) {
        Ok(token_details) => token_details,
        Err(e) => {
            return HttpResponse::BadGateway()
                .json(serde_json::json!({"status": "fail", "message": format_args!("{}", e)}));
        }
    };

    let refresh_token_details = match token_service::generate_jwt_token(
        user.id,
        data.env.refresh_token_max_age,
        data.env.refresh_token_private_key.to_owned(),
    ) {
        Ok(token_details) => token_details,
        Err(e) => {
            return HttpResponse::BadGateway()
                .json(serde_json::json!({"status": "fail", "message": format_args!("{}", e)}));
        }
    };

    HttpResponse::Ok()
        .json(json!({"status": "success", "access": access_token_details.token.clone().unwrap() , "refresh":refresh_token_details.token.clone().unwrap()}))
}
#[post("/refresh")]
async fn refresh_token_handler(
    data: web::Data<AppState>,
    body: web::Json<RefreshSchema>,
) -> impl Responder {

    let refresh_token = body.refresh.to_owned();
    if refresh_token.is_empty() {
        return HttpResponse::BadRequest().json(
            serde_json::json!({"status": "fail", "message": "Refresh token is required"}),
        );
    }


    let refresh_token_details =
        match token_service::verify_jwt_token(data.env.refresh_token_public_key.to_owned(), &refresh_token)
        {
            Ok(token_details) => token_details,
            Err(_) => {
                return HttpResponse::Forbidden().json(
                    serde_json::json!({"status": "fail", "message": "Invalid refresh token"}),
                );
            }
        };
    let result = data.redis_client.get_async_connection().await;
    println!("{}", result.is_err());
    let mut redis_client = match result {
        Ok(redis_client) => redis_client,
        Err(e) => {
            return HttpResponse::Forbidden().json(
                serde_json::json!({"status": "fail", "message": format!("Could not connect to Redis: {}", e)}),
            );
        }
    };

    let redis_result: redis::RedisResult<String> = redis_client
        .get(refresh_token_details.token_uuid.to_string())
        .await;
    
    let already_consumed_token = match redis_result {
        Ok(_token) => true,
        Err(_) => false
    };
    if already_consumed_token {
        return HttpResponse::Forbidden()
            .json(serde_json::json!({"status": "fail", "message": "The refresh token has already been used"}));
    }

    let user_id_uuid = refresh_token_details.user_id.to_owned();
    let query_result = sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", user_id_uuid)
        .fetch_optional(&data.db)
        .await
        .unwrap();

    if query_result.is_none() {
        return HttpResponse::Forbidden()
            .json(serde_json::json!({"status": "fail", "message": "the user belonging to this token no logger exists"}));
    }

    let user = query_result.unwrap();

    let access_token_details = match token_service::generate_jwt_token(
        user.id,
        data.env.access_token_max_age,
        data.env.access_token_private_key.to_owned(),
    ) {
        Ok(token_details) => token_details,
        Err(e) => {
            return HttpResponse::BadGateway()
                .json(serde_json::json!({"status": "fail", "message": format_args!("{:?}", e)}));
        }
    };

    

    let redis_result: redis::RedisResult<()> = redis_client
        .set_ex(
            refresh_token_details.token_uuid.to_string(),
            user.id.to_string(),
            (data.env.access_token_max_age * 60) as usize,
        )
        .await;
    
    let refresh_token_details = match token_service::generate_jwt_token(
        user.id,
        data.env.refresh_token_max_age,
        data.env.refresh_token_private_key.to_owned(),
    ) {
        Ok(token_details) => token_details,
        Err(e) => {
            return HttpResponse::BadGateway()
                .json(serde_json::json!({"status": "fail", "message": format_args!("{}", e)}));
        }
    };

    if redis_result.is_err() {
        return HttpResponse::UnprocessableEntity().json(
            serde_json::json!({"status": "error", "message": format_args!("{:?}", redis_result.unwrap_err())}),
        );
    }

    HttpResponse::Ok()
        .json(serde_json::json!({"status": "success", "access": access_token_details.token.unwrap(), "refresh": refresh_token_details.token.unwrap()}))
}


#[get("/check")]
async fn check_token_handler(
    req: HttpRequest,
    data: web::Data<AppState>,
    _: jwt_auth::JwtMiddleware,
) -> impl Responder {
    let ext = req.extensions();
    let user_id = ext.get::<uuid::Uuid>().unwrap();

    let user = sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", user_id)
        .fetch_one(&data.db)
        .await
        .unwrap();

    let json_response = serde_json::json!({
        "status":  "success",
        "data": serde_json::json!({
            "user": filter_user_record(&user)
        })
    });

    HttpResponse::Ok().json(json_response)
}



pub fn config(conf: &mut web::ServiceConfig) {
    let scope = web::scope("/api/auth")
        .service(login_user_handler)
        .service(check_token_handler)
        .service(refresh_token_handler);
    conf.service(scope);
}
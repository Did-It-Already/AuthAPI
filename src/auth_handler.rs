use crate::{
    jwt_auth,
    user_model::{LoginUserSchema,  User, RefreshSchema},
    user_service::{filter_user_record,fetch_user_by_id_query},
    token_service, AppState,
    ldap_service::get_admin_ldap
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
use uuid::Uuid;
use ldap3::{LdapConn, Scope, SearchEntry};
use tokio::runtime::Runtime;
use std::thread;
#[post("/login")]
async fn login_user_handler(
    body: web::Json<LoginUserSchema>,
    data: web::Data<AppState>,
) -> impl Responder {
    let base_dn = "ou=dia,dc=diditalready,dc=com";
    let email = body.email.as_str();
    let filter = format!("(&(objectClass=inetOrgPerson)(mail={}))",email);
    let ldap = get_admin_ldap(&data.ldap_pool, &data.env.ldap_admin_dn,&data.env.ldap_admin_password).await;
    let mut ldap = match ldap {
        Ok(ldap) => ldap,
        Err(err) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "error","message": format!("{:?}", err)}));
        }
    };
    let search_result = ldap
        .search(
            &base_dn,
            Scope::Subtree,
            &filter, 
            vec!["uid"],
        )
        .await;
    let search_result = match search_result {
        Ok(search_result) => search_result,
        Err(err) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "error","message": format!("{:?}", err)}));
        }
    };

    let (rs,_res) = match search_result.success() {
        Ok(search_result) => search_result,
        Err(err) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "error","message": format!("{:?}", err)}));
        }
    };
    if !(rs.len() > 0) {
        return HttpResponse::Conflict().json(
            serde_json::json!({"status": "fail","message": "Invalid email or password"}),
        );    
    }




    // check password in ldap
    let password = body.password.as_str();

    let mut user_ldap = match data.ldap_pool.get().await {
        Ok(user_ldap) => user_ldap,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "error","message": format!("Could not connect to LDAP: {}", e)}));
        }
    };



    let user_id = match rs.into_iter().next() {
        Some(entry) => {
            let user = SearchEntry::construct(entry);
            let user_id = user.attrs.get("uid").unwrap().get(0).unwrap().parse::<u64>().unwrap();
            user_id
        },
        None => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "error","message": "User not found"}));
        }
    };

    let dn = format!("uid={},{}", user_id, base_dn);
    let password = body.password.as_str(); // The password to check

    let bind_result = match user_ldap.simple_bind(dn.as_str(), password).await{
        Ok(bind_result) =>bind_result,
        Err(err) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "error","message": "Invalid email or password"}));
        }
    };  
    let bind_result = match bind_result.success() {
        Ok(_) => {},
        Err(err) => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "error","message": "Invalid email or password"}));
        }
    };  

    


    let access_token_details = match token_service::generate_jwt_token(
        user_id,
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
        user_id,
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

    let user_id= refresh_token_details.user_id;

    let base_dn = "ou=dia,dc=diditalready,dc=com";
    let filter = format!("(&(objectClass=inetOrgPerson)(uid={}))",user_id);
    let ldap = get_admin_ldap(&data.ldap_pool,&data.env.ldap_admin_dn,&data.env.ldap_admin_password).await;
    let mut ldap = match ldap {
        Ok(ldap) => ldap,
        Err(err) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "error","message": format!("{:?}", err)}));
        }
    };
    let search_result = ldap
        .search(
            &base_dn,
            Scope::Subtree,
            &filter, 
            vec!["uid"],
        )
        .await;
    let search_result = match search_result {
        Ok(search_result) => search_result,
        Err(err) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "error","message": format!("{:?}", err)}));
        }
    };

    let (rs,_res) = match search_result.success() {
        Ok(search_result) => search_result,
        Err(err) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "error","message": format!("{:?}", err)}));
        }
    };
    if !(rs.len() > 0) {
        return HttpResponse::Conflict().json(
            serde_json::json!({"status": "fail","message": "the user belonging to this token no longer exists"}),
        );    
    }


    let access_token_details = match token_service::generate_jwt_token(
        user_id,
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
            user_id.to_string(),
            (data.env.access_token_max_age * 60) as usize,
        )
        .await;
    
    let refresh_token_details = match token_service::generate_jwt_token(
        user_id,
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
    let user_id = ext.get::<u64>().unwrap().to_owned();
    let base_dn = "ou=dia,dc=diditalready,dc=com";
    let filter = format!("(&(objectClass=inetOrgPerson)(uid={}))",user_id);
    let ldap = get_admin_ldap(&data.ldap_pool,&data.env.ldap_admin_dn,&data.env.ldap_admin_password).await;
    let mut ldap = match ldap {
        Ok(ldap) => ldap,
        Err(err) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "error","message": format!("{:?}", err)}));
        }
    };
    let search_result = ldap
        .search(
            &base_dn,
            Scope::Subtree,
            &filter, 
            vec!["mail"],
        )
        .await;
    let search_result = match search_result {
        Ok(search_result) => search_result,
        Err(err) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "error","message": format!("{:?}", err)}));
        }
    };

    let (rs,_res) = match search_result.success() {
        Ok(search_result) => search_result,
        Err(err) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "error","message": format!("{:?}", err)}));
        }
    };
    if !(rs.len() > 0) {
        return HttpResponse::Conflict().json(
            serde_json::json!({"status": "fail","message": "the user belonging to this token no longer exists"}),
        );    
    }

    let email = match rs.into_iter().next() {
        Some(entry) => {
            let user = SearchEntry::construct(entry);
            let email = user.attrs.get("mail").unwrap().get(0).unwrap().to_string();
            email
        },
        None => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "error","message": "Mail not found"}));
        }
    };

    let json_response = serde_json::json!({
        "status":  "success",
        "data": serde_json::json!({
            "user": {
                "id": user_id,
                "email": email,
                "user_id": user_id
            }
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
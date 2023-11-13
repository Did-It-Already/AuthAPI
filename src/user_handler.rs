use crate::{
    user_model::{RegisterUserSchema, User},
    user_service::filter_user_record, AppState,
    ldap_service::get_admin_ldap
};
use actix_web::{
     post, web, HttpResponse, Responder,delete
};
use argon2::{
    password_hash::{rand_core::OsRng,  PasswordHasher, SaltString},
    Argon2,
};
use ldap3::{LdapConnAsync, Scope, SearchEntry};
use ldap3::result::Result;
use std::collections::HashSet;
use sqlx::Row;
use uuid::Uuid;

#[post("/")]
async fn register_user_handler(
    body: web::Json<RegisterUserSchema>,
    data: web::Data<AppState>,
) -> impl Responder {
    
    let email = body.email.as_str();
    let password = body.password.as_str();
    let user_id = body.user_id.to_string();
    let username: Vec<&str> = email.split('@').collect();
    let username = username[0];
    let base_dn = "ou=dia,dc=diditalready,dc=com";
    let dn = format!("uid={},{}", user_id, base_dn);
    let filter = format!("(&(objectClass=inetOrgPerson)(|(mail={})(uid={})))", email,user_id);
    // check if user exists
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
            vec!["1.1"],
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
    if rs.len() > 0 {
        return HttpResponse::Conflict().json(
            serde_json::json!({"status": "fail","message": "User with that email or uid already exists"}),
        );    
    }

    let attrs: Vec<(&str, HashSet<&str>)> = vec![
    ("objectClass", vec!["inetOrgPerson"].into_iter().collect()),
    ("uid", vec![user_id.as_str()].into_iter().collect()),
    ("mail", vec![email].into_iter().collect()),
    ("sn", vec![username].into_iter().collect()),
    ("cn", vec![email].into_iter().collect()),
    ("userPassword", vec![password].into_iter().collect()),
    
];
    

    let result = ldap.add(&dn, attrs).await;
    let result = match result {
        Ok(result) => result,
        Err(err) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "error","message": format!("{:?}", err)}));
        }
    };
    match result.success() {
        Ok(_) => {
            let user_response = serde_json::json!({"status": "success","data": serde_json::json!({
                "user": {
                    "id": user_id,
                    "email": email,
                    "user_id": user_id
                }
            })});

            return HttpResponse::Ok().json(user_response);
        }
        Err(err) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "error","message": format!("{:?}", err)}));
        }
    }



}

#[delete("/{id}")]
async fn delete_user_handler(
    path: web::Path<u64>,
    data: web::Data<AppState>,
) -> impl Responder {
    let id =path.into_inner();
    let base_dn = "ou=dia,dc=diditalready,dc=com";
    let filter = format!("(&(objectClass=inetOrgPerson)(uid={}))",id);
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
            vec!["1.1"],
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
            serde_json::json!({"status": "fail","message": "User does not exist"}),
        );    
    }
    let dn = format!("uid={},{}", id, base_dn);
    let result = ldap.delete(&dn).await;
    let result = match result {
        Ok(result) => {
            let response = serde_json::json!({"status": "success","message": "User deleted successfully"});
            return HttpResponse::Ok().json(response);
        }
        Err(err) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "error","message": format!("{:?}", err)}));
        }
    };

}



pub fn config(conf: &mut web::ServiceConfig) {
    let scope = web::scope("/api/user")
        .service(register_user_handler)
        .service(delete_user_handler);
    conf.service(scope);
}
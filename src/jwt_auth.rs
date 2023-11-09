use core::fmt;
use std::future::{ready, Ready};

use actix_web::error::{ErrorInternalServerError, ErrorUnauthorized};
use actix_web::{dev::Payload, Error as ActixWebError};
use actix_web::{http, web, FromRequest, HttpRequest, HttpMessage};
use futures::executor::block_on;
use serde::{Serialize};
use ldap3::{LdapConn, Scope, SearchEntry};

use crate::user_model::User;
use crate::token_service;
use crate::AppState;
use crate::ldap_service::get_admin_ldap;
use uuid::Uuid;

use crate::user_service::{fetch_user_by_id_query};

#[derive(Debug, Serialize)]
struct ErrorResponse {
    status: String,
    message: String,
}

impl fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", serde_json::to_string(&self).unwrap())
    }
}

pub struct JwtMiddleware {
    pub user_id: u64,
}

impl FromRequest for JwtMiddleware {
    type Error = ActixWebError;
    type Future = Ready<Result<Self, Self::Error>>;
    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let data = req.app_data::<web::Data<AppState>>().unwrap();

        let access_token = req.headers()
                    .get(http::header::AUTHORIZATION)
                    .map(|h| h.to_str().unwrap().split_at(7).1.to_string());
            


        if access_token.is_none() {
            let json_error = ErrorResponse {
                status: "fail".to_string(),
                message: "No token found".to_string(),
            };
            return ready(Err(ErrorUnauthorized(json_error)));
        }

        let token_details = match token_service::verify_jwt_token(
            data.env.access_token_public_key.to_owned(),
            &access_token.unwrap(),
        ) {
            Ok(token_details) => token_details,
            Err(e) => {
                let json_error = ErrorResponse {
                    status: "Fail".to_string(),
                    message: "Invalid Token".to_string(),
                };
                return ready(Err(ErrorUnauthorized(json_error)));
            }
        };

        let user_id= token_details.user_id;
        let user_exists_result = async move {

        let base_dn = "ou=dia,dc=diditalready,dc=com";
        let filter = format!("(&(objectClass=inetOrgPerson)(uid={}))",user_id);
        let ldap = get_admin_ldap(&data.ldap_pool).await;
        let mut ldap = match ldap {
            Ok(ldap) => ldap,
            Err(err) => return Err(ErrorInternalServerError("LDAP connection error".to_string())),
        };
            let search_result = ldap
                .search(
                    &base_dn,
                    Scope::Subtree,
                    &filter, 
                    vec!["uid"],
                )
                .await.unwrap();

            let (rs,_res) =search_result.success().unwrap() ;
            if rs.len() == 0 {
                return Err(ErrorUnauthorized("User not found".to_string()));
            }
            return Ok(());
            
        };

        req.extensions_mut()
            .insert(token_details.user_id);

        match block_on(user_exists_result) {
            Ok(_user) => ready(Ok(JwtMiddleware {
                user_id: token_details.user_id
            })),
            Err(error) => ready(Err(error)),
        }
    }
}

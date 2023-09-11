use core::fmt;
use std::future::{ready, Ready};

use actix_web::error::{ErrorInternalServerError, ErrorUnauthorized};
use actix_web::{dev::Payload, Error as ActixWebError};
use actix_web::{http, web, FromRequest, HttpRequest, HttpMessage};
use futures::executor::block_on;
use serde::{Serialize};

use crate::model::User;
use crate::token;
use crate::AppState;

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
    pub user_id: uuid::Uuid,
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

        let token_details = match token::verify_jwt_token(
            data.env.access_token_public_key.to_owned(),
            &access_token.unwrap(),
        ) {
            Ok(token_details) => token_details,
            Err(e) => {
                let json_error = ErrorResponse {
                    status: "fail".to_string(),
                    message: format!("{:?}", e),
                };
                return ready(Err(ErrorUnauthorized(json_error)));
            }
        };

        let user_id_uuid = token_details.user_id.to_owned();
        let user_exists_result = async move {


            let query_result =
                sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", user_id_uuid)
                    .fetch_optional(&data.db)
                    .await;

            match query_result {
                Ok(Some(user)) => Ok(user),
                Ok(None) => {
                    let json_error = ErrorResponse {
                        status: "Failed".to_string(),
                        message: "the user belonging to this token no longer exists".to_string(),
                    };
                    Err(ErrorUnauthorized(json_error))
                }
                Err(_) => {
                    let json_error = ErrorResponse {
                        status: "Error".to_string(),
                        message: "Failed to check user existence".to_string(),
                    };
                    Err(ErrorInternalServerError(json_error))
                }
            }
        };

        req.extensions_mut()
            .insert::<uuid::Uuid>(token_details.user_id.to_owned());

        match block_on(user_exists_result) {
            Ok(_user) => ready(Ok(JwtMiddleware {
                user_id: token_details.user_id.to_owned()
            })),
            Err(error) => ready(Err(error)),
        }
    }
}

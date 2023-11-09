use crate::{
    user_model::User,
    response::FilteredUser
};
use uuid::Uuid;

pub fn filter_user_record(user: &User) -> FilteredUser {
    FilteredUser {
        user_id: user.user_id,
        email: user.email.to_owned(),
        id: user.id.to_owned()
    }
}

pub fn fetch_user_by_id_query(param: &u64) -> (&'static str, &u64) {
    let query = "SELECT * FROM users WHERE id = $1";
    (query, param)
}
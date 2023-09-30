use crate::{
    user_model::User,
    response::FilteredUser
};

pub fn filter_user_record(user: &User) -> FilteredUser {
    FilteredUser {
        id: user.id.to_string(),
        email: user.email.to_owned(),
    }
}
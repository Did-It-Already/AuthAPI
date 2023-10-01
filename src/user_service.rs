use crate::{
    user_model::User,
    response::FilteredUser
};

pub fn filter_user_record(user: &User) -> FilteredUser {
    FilteredUser {
        user_id: user.user_id,
        email: user.email.to_owned(),
    }
}
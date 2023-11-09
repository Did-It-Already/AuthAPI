use deadpool_ldap::{Manager, Pool};
use deadpool::managed::Object;
use deadpool::managed::PoolError;
use ldap3::result::LdapError;
#[derive(Debug)]
pub enum MyError {
    PoolError(deadpool::managed::PoolError<LdapError>),
    LdapError(LdapError),
}

impl From<deadpool::managed::PoolError<LdapError>> for MyError {
    fn from(err: deadpool::managed::PoolError<LdapError>) -> Self {
        MyError::PoolError(err)
    }
}

impl From<LdapError> for MyError {
    fn from(err: LdapError) -> Self {
        MyError::LdapError(err)
    }
}

pub async fn get_admin_ldap(pool: &Pool) -> Result<Object<Manager>, MyError> {
    let mut ldap = pool.get().await?;
    let bind_result = ldap.simple_bind("cn=admin, dc=diditalready,dc=com", "admin").await?;
    match bind_result.success() {
        Ok(_) => println!("✅LDAP Bind successful"),
        Err(err) => return Err(MyError::from(err)),
    }
    Ok(ldap)
}
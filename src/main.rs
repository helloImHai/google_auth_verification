use crate::auth::{AuthenticationError, AuthVerifierClient };
use jsonwebtoken::errors::{ErrorKind};

mod auth;

#[tokio::main]
async fn main() {
    let mut auth_verifier_client = AuthVerifierClient::new(None);
    let res = auth_verifier_client
        .verify_generic_token("# insert key")
        .await;
    match res {
        Ok(token_data) => {
            println!("{}", token_data.claims);
        },
        Err(AuthenticationError::JwtError(x)) => {
            match x.kind() {
                ErrorKind::ExpiredSignature => (),
                x => {
                    println!("Another error {:?}", x)
                }
            }
        },
        Err(e) => {
            println!("{:?}", e);
        }
    }
}

# Rust Google Authentication Library

A simple Rust library for verifying Google auth tokens.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
google-auth-verifier = "0.1.4"
```

## Usage
```rust 
use google_auth_verifier::AuthVerifierClient;

#[tokio::main]
async fn main() {
    // None for auth verifier options will use default options
    let mut auth_verifier_client = AuthVerifierClient::new(None);
    // verify_generic_token will work for both firebase and oauth tokens
    let res = auth_verifier_client.verify_generic_token("# insert key here").await;

    match res {
        Ok(token_info) => {
            println!("Token is valid: {:?}", token_info);
        },
        Err(e) => {
            eprintln!("Failed to verify token: {:?}", e);
        },
    }
}
```

## Contributing
Contributions are welcome! Please open an issue or submit a pull request.

## Acknowledgements
- The api is inspired by the [google auth library in python](https://github.com/googleapis/google-auth-library-python). 
- [May Lukas's medium article](https://medium.com/@maylukas/firebase-token-authentication-in-rust-a1885f0982df) was also a 
major inspiration and resource to understand JWTs.
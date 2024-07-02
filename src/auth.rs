use std::num::NonZeroUsize;
use lru::LruCache;
use jsonwebtoken;
use jsonwebtoken::{DecodingKey, Header, TokenData, Validation};
use jsonwebtoken::errors::Error as JwtValidationError;
use serde_json::Value as JsonValue;

const DEFAULT_CACHE_SIZE: usize = 20;
const FIREBASE_APIS_CERTS_URL: &str = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";
const OAUTH2_APIS_CERTS_URL: &str = "https://www.googleapis.com/oauth2/v1/certs";

pub enum GoogleAuthProvider {
    Firebase,
    OAuth2,
}

#[derive(Debug)]
pub enum AuthenticationError {
    InvalidHeader(String),
    InvalidPemKey(String),
    UnableToFetchPublicKey(String),
    PublicKeyMissing,
    MissingKid,
    JwtError(JwtValidationError),
}

pub struct AuthVerifierClientOptions {
    pub cache_size: NonZeroUsize,
    pub aud: Option<Vec<String>>,
    pub validate_exp: bool,
}

pub struct AuthVerifierClient {
    pub_key_cache: LruCache<String, String>,
    options: AuthVerifierClientOptions,
}

impl AuthVerifierClient {
    pub fn new(options: Option<AuthVerifierClientOptions>) -> AuthVerifierClient {
        let options = options
            .unwrap_or_else(|| AuthVerifierClientOptions {
                cache_size: NonZeroUsize::new(DEFAULT_CACHE_SIZE).unwrap(),
                aud: None,
                validate_exp: true,
            });
        AuthVerifierClient {
            pub_key_cache: LruCache::new(options.cache_size),
            options,
        }
    }

    fn get_pub_key_url(auth_provider: &GoogleAuthProvider) -> &str {
        match auth_provider {
            GoogleAuthProvider::Firebase => FIREBASE_APIS_CERTS_URL,
            GoogleAuthProvider::OAuth2 => OAUTH2_APIS_CERTS_URL,
        }
    }

    async fn fetch_keys(&mut self, auth_provider: &GoogleAuthProvider) -> Result<(), AuthenticationError> {
        let http_response = reqwest::get(Self::get_pub_key_url(auth_provider)).await
            .map_err(|e| AuthenticationError::UnableToFetchPublicKey(e.to_string()))?;
        let map = match http_response.json::<JsonValue>().await
            .map_err(|e| AuthenticationError::UnableToFetchPublicKey(e.to_string()))?
            .as_object() {
            Some(map) => map.clone(),
            None => return Err(AuthenticationError::UnableToFetchPublicKey(String::from("Map is empty")))
        };
        for (kid, pub_key) in map {
            self.pub_key_cache.put(
                kid.to_string(),
                String::from(pub_key.as_str().unwrap()),
            );
        }
        return Ok(());
    }

    async fn get_public_key_from_kid(&mut self, kid: &str, auth_providers: &Vec<GoogleAuthProvider>)
                               -> Result<String, AuthenticationError> {
        if let Some(public_key) = self.pub_key_cache.get_mut(kid) {
            return Ok(public_key.clone());
        }
        for auth_provider in auth_providers.iter() {
            let _ = self.fetch_keys(auth_provider).await?;
        }
        if let Some(public_key) = self.pub_key_cache.get_mut(kid) {
            return Ok(public_key.clone());
        }
        Err(AuthenticationError::PublicKeyMissing)
    }

    pub async fn verify_generic_token(&mut self, token: &str) -> Result<TokenData<JsonValue>, AuthenticationError> {
        self.verify_token(token, &vec![GoogleAuthProvider::Firebase, GoogleAuthProvider::OAuth2]).await
    }

    pub async fn verify_firebase_token(&mut self, token: &str) -> Result<TokenData<JsonValue>, AuthenticationError> {
        self.verify_token(token, &vec![GoogleAuthProvider::Firebase]).await
    }

    pub async fn verify_oauth_token(&mut self, token: &str) -> Result<TokenData<JsonValue>, AuthenticationError> {
        self.verify_token(token, &vec![GoogleAuthProvider::OAuth2]).await
    }

    async fn verify_token(&mut self, token: &str, providers: &Vec<GoogleAuthProvider>)
                    -> Result<TokenData<JsonValue>, AuthenticationError> {
        let header: Header = jsonwebtoken::decode_header(token)
            .map_err(|e| AuthenticationError::InvalidHeader(e.to_string()))?;

        let token_kid: String = match header.kid {
            Some(ref kid) => kid.clone(),
            _ => return Err(AuthenticationError::MissingKid)
        };

        let public_key: String = self.get_public_key_from_kid(&token_kid, providers).await?;
        let mut validation_algo = Validation::new(header.alg);
        match &self.options.aud {
            Some(aud) => validation_algo.set_audience(&aud),
            None => validation_algo.validate_aud = false
        }
        validation_algo.validate_exp = self.options.validate_exp;
        let decoding_key = DecodingKey::from_rsa_pem(public_key.as_bytes())
            .map_err(|e| AuthenticationError::InvalidPemKey(e.to_string()))?;
        jsonwebtoken::decode::<JsonValue>(token, &decoding_key, &validation_algo).map_err(|e| {
            AuthenticationError::JwtError(e)
        })
    }
}
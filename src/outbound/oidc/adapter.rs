use crate::domain::auth::{
    OIDCCallbackError, OIDCCallbackParams, OIDCCallbackResult, OIDCLoginParams, OIDCLoginResult,
    OIDCPort, OIDCRefreshError, OIDCRefreshParams, OIDCRefreshResult, SessionTokens,
};
use crate::outbound::oidc::adapter::Error::JWTDecodeError;
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use oauth2::{AccessToken, EndpointMaybeSet, EndpointNotSet, EndpointSet, HttpClientError, url};
use openidconnect::core::{CoreResponseType, CoreTokenResponse};
use openidconnect::{
    AdditionalClaims, AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    DiscoveryError, IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, RefreshToken, Scope, TokenResponse, UserInfoClaims,
    core::{CoreClient, CoreGenderClaim, CoreProviderMetadata},
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::string::FromUtf8Error;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::error;
use tracing::log::debug;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    ReqwestError(#[from] reqwest::Error),

    #[error(transparent)]
    URLParseError(#[from] url::ParseError),

    #[error(transparent)]
    DiscoveryError(#[from] DiscoveryError<HttpClientError<reqwest::Error>>),

    #[error(transparent)]
    Base64DecodeError(#[from] base64::DecodeError),

    #[error(transparent)]
    UTF8Error(#[from] FromUtf8Error),

    #[error(transparent)]
    SerdeJSONError(#[from] serde_json::Error),

    #[error("jwt decode error")]
    JWTDecodeError,
}

#[derive(Debug, Deserialize, Serialize)]
struct RancherClaims {
    user_name: Option<String>,
    groups: Option<Vec<String>>,
}
impl AdditionalClaims for RancherClaims {}

#[derive(Debug, Clone)]
pub struct OIDCAdapter {
    http_client: reqwest::Client,
    oidc_client: CoreClient<
        EndpointSet,
        EndpointNotSet,
        EndpointNotSet,
        EndpointNotSet,
        EndpointMaybeSet,
        EndpointMaybeSet,
    >,
}

pub struct NewOIDCServiceParams {
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
}

impl OIDCAdapter {
    pub async fn new(params: NewOIDCServiceParams) -> Result<Self, Error> {
        tracing::debug!(
            issuer = params.issuer_url,
            client_id = params.client_id.clone(),
            "retrieving oidc metadata"
        );
        let issuer_url = IssuerUrl::new(params.issuer_url)?;
        let client_id = ClientId::new(params.client_id);
        let client_secret = ClientSecret::new(params.client_secret);

        let http_client = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        let provider_metadata =
            CoreProviderMetadata::discover_async(issuer_url, &http_client).await?;
        tracing::debug!("retrieved oidc metadata");

        let oidc_client =
            CoreClient::from_provider_metadata(provider_metadata, client_id, Some(client_secret))
                .set_redirect_uri(RedirectUrl::new(params.redirect_url.clone())?);

        Ok(Self {
            http_client,
            oidc_client,
        })
    }
}

#[async_trait]
impl OIDCPort for OIDCAdapter {
    async fn login(&self, _params: OIDCLoginParams) -> OIDCLoginResult {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let (authorization_url, csrf_token, nonce) = self
            .oidc_client
            .authorize_url(
                AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("openid".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .add_scope(Scope::new("offline_access".to_string()))
            .set_pkce_challenge(pkce_challenge)
            //.set_redirect_uri(Cow::Owned(RedirectUrl::new("http://localhost:1111/foo".to_string())?))
            .url();

        OIDCLoginResult {
            authorization_url: authorization_url.as_str().to_string(),
            csrf_token: csrf_token.into_secret(),
            nonce: nonce.secret().to_string(),
            pkce_verifier: pkce_verifier.into_secret(),
        }
    }

    async fn callback(
        &self,
        params: OIDCCallbackParams,
    ) -> Result<OIDCCallbackResult, OIDCCallbackError> {
        let authorization_code = AuthorizationCode::new(params.code);

        let response = self
            .oidc_client
            .exchange_code(authorization_code)?
            .set_pkce_verifier(PkceCodeVerifier::new(params.pkce_code_verifier))
            .request_async(&self.http_client)
            .await
            .map_err(|e| {
                match e {
                    openidconnect::RequestTokenError::ServerResponse(response) => {
                        debug!("Server response: {:?}", response);
                    }
                    openidconnect::RequestTokenError::Request(err) => {
                        debug!("Request error: {:?}", err)
                    }
                    openidconnect::RequestTokenError::Parse(serde_error, _) => {
                        debug!("Parse error: {:?}", serde_error)
                    }
                    openidconnect::RequestTokenError::Other(err) => {
                        debug!("Other error: {:?}", err)
                    }
                }

                OIDCCallbackError::RequestTokenError
            })?;

        let id_token_verifier = self.oidc_client.id_token_verifier();
        let claims = response
            .id_token()
            .ok_or(OIDCCallbackError::NoIDTokenError)?
            .claims(&id_token_verifier, &Nonce::new(params.nonce))?;
        let subject = claims.subject().to_string();
        let username = claims
            .name()
            .map(|i| i.get(None).map(|i| i.to_string()).unwrap_or_default());

        let session_tokens: SessionTokens = response
            .try_into()
            .map_err(|_e| OIDCCallbackError::TokenDecodeError)?;
        let user_info_claims: UserInfoClaims<RancherClaims, CoreGenderClaim> = self
            .oidc_client
            .user_info(AccessToken::new(session_tokens.access_token.clone()), None)?
            .request_async(&self.http_client)
            .await
            .map_err(|e| {
                error!("failed to fetch user info: {}", e);
                OIDCCallbackError::UserInfoError
            })?;

        // clean up groups, e.g. "openldap_group://cn=lichen-admins,cn=lichen,cn=groups,dc=lichen,dc=de"
        let group_regex = Regex::new(r"cn=([^,]+)")?;
        let groups = user_info_claims.additional_claims().groups.clone();
        let groups = groups
            .unwrap_or_default()
            .iter()
            .filter_map(|group| {
                group_regex
                    .captures(group)
                    .and_then(|captures| captures.get(1))
                    .map(|m| m.as_str().to_string())
            })
            .collect();

        Ok(OIDCCallbackResult {
            session_tokens,
            subject,
            groups,
            username,
        })
    }

    async fn refresh(
        &self,
        params: OIDCRefreshParams,
    ) -> Result<OIDCRefreshResult, OIDCRefreshError> {
        let response = self
            .oidc_client
            .exchange_refresh_token(&RefreshToken::new(params.refresh_token))?
            .request_async(&self.http_client)
            .await
            .map_err(|e| {
                error!("failed to refresh token: {}", e);
                OIDCRefreshError::RefreshTokenError
            })?;
        let session_tokens: SessionTokens = response
            .try_into()
            .map_err(|_e| OIDCRefreshError::TokenDecodeError)?;

        Ok(OIDCRefreshResult { session_tokens })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JWTToken {
    pub(crate) exp: u64,
}

impl TryFrom<CoreTokenResponse> for SessionTokens {
    type Error = ();

    fn try_from(value: CoreTokenResponse) -> Result<Self, Self::Error> {
        let id_token = value.id_token().ok_or(())?.to_string();

        let access_token = value.access_token();
        let access_token = access_token.clone().into_secret();
        let access_token_expires_at = jwt_expiry(access_token.as_str())
            .ok()
            .map(|exp| UNIX_EPOCH + Duration::from_secs(exp))
            .unwrap_or_else(SystemTime::now);

        let refresh_token = value.refresh_token().ok_or(())?;
        let refresh_token = refresh_token.clone().into_secret();

        let refresh_token_expires_at = jwt_expiry(refresh_token.as_str())
            .ok()
            .map(|exp| UNIX_EPOCH + Duration::from_secs(exp))
            .unwrap_or_else(SystemTime::now);

        Ok(SessionTokens {
            access_token,
            refresh_token,
            id_token,
            access_token_expires_at,
            refresh_token_expires_at,
        })
    }
}

fn jwt_expiry(jwt: &str) -> Result<u64, Error> {
    let payload = jwt.split('.').nth(1).ok_or_else(|| JWTDecodeError)?;
    let payload = STANDARD_NO_PAD.decode(payload)?;
    let payload = String::from_utf8(payload)?;
    let jwt_decoded: JWTToken = serde_json::from_str(payload.as_str())?;
    Ok(jwt_decoded.exp)
}

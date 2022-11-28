#![allow(clippy::type_complexity)]

use oidc4vp::presentation_exchange::VpTokenIdToken;
use openidconnect::{
    core::{
        CoreAuthDisplay, CoreAuthPrompt, CoreAuthenticationFlow, CoreErrorResponseType,
        CoreGenderClaim, CoreJsonWebKeyType, CoreJsonWebKeyUse, CoreJweContentEncryptionAlgorithm,
        CoreResponseType, CoreRevocableToken, CoreRevocationErrorResponse,
        CoreTokenIntrospectionResponse, CoreTokenType,
    },
    url::Url,
    AdditionalClaims, AuthUrl, ClaimsVerificationError, ClientId, CsrfToken, EmptyExtraTokenFields,
    ErrorResponseType, IssuerUrl, JsonWebKey, JsonWebKeyId, JsonWebKeySet, JsonWebTokenError,
    JwsSigningAlgorithm, Nonce, PrivateSigningKey, RedirectUrl, RequestUrl, Scope,
    SignatureVerificationError, SigningError, StandardErrorResponse, StandardTokenResponse,
};
use provider::ProviderDiscoveryMetadata;
use serde::{Deserialize, Serialize};
use ssi::{
    did::VerificationRelationship,
    did_resolve::{get_verification_methods, DIDResolver},
    jwk::{self, JWK},
    jws,
};

pub mod provider;
pub mod rp;
pub mod utils;

pub use openidconnect;

struct AuthorizationRequestParams {
    scope: Scope,
    response_type: CoreResponseType,
    redirect_uri: RedirectUrl,
    id_token_hint: Option<IdToken>,
    claims: Option<Vec<IdTokenClaims>>,
    client_metadata: Option<rp::RPMetadata>,
    client_metadata_uri: Option<utils::MetadataUrl>,
    // request: Option<serde_json::Value>, // don't think it's supported in openidconnect-rs
    request_uri: Option<RequestUrl>,
    id_token_type: Option<CoreTokenType>,
}
type IdTokenFields = openidconnect::IdTokenFields<
    IdTokenAdditionalClaims,
    EmptyExtraTokenFields,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    SigningAlgorithm,
    CoreJsonWebKeyType,
>;
type TokenResponse = StandardTokenResponse<IdTokenFields, CoreTokenType>;

pub struct Client(
    openidconnect::Client<
        IdTokenAdditionalClaims,
        CoreAuthDisplay,
        CoreGenderClaim,
        CoreJweContentEncryptionAlgorithm,
        SigningAlgorithm,
        CoreJsonWebKeyType,
        CoreJsonWebKeyUse,
        WebKey,
        CoreAuthPrompt,
        StandardErrorResponse<AuthErrorResponseType>, // TODO also use SIOP errors
        TokenResponse,
        CoreTokenType,
        CoreTokenIntrospectionResponse,
        CoreRevocableToken,
        CoreRevocationErrorResponse,
    >,
);

impl Client {
    fn new(client_id: ClientId, issuer: IssuerUrl, auth_url: AuthUrl) -> Self {
        Self(openidconnect::Client::new(
            client_id,
            None,
            issuer,
            auth_url,
            None,
            None,
            JsonWebKeySet::new(vec![]),
        ))
    }

    // TODO good idea?
    fn from_provider_metadata(
        provider_metadata: ProviderDiscoveryMetadata,
        client_id: ClientId,
    ) -> Self {
        Self(openidconnect::Client::from_provider_metadata(
            provider_metadata.0,
            client_id,
            None,
        ))
    }

    fn authorize_url(&self, params: AuthorizationRequestParams) -> (Url, CsrfToken, Nonce) {
        self.0
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(params.scope)
            .url()
    }
}

pub struct KeySet(JsonWebKeySet<SigningAlgorithm, CoreJsonWebKeyType, CoreJsonWebKeyUse, WebKey>);

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum IdTokenType {
    SubjectSigned,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct IdTokenAdditionalClaims {
    // TODO When the sub Claim value is the base64url encoded representation of the thumbprint, a sub_jwk Claim is present, with its value being the public key used to check the signature of the ID Token
    // pub sub: String, // TODO either the base64url encoded representation of the thumbprint of the key in the sub_jwk Claim or a Decentralized Identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_jwk: Option<JWK>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vp_token: Option<VpTokenIdToken>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Hash, Eq)]
#[serde(transparent)]
pub struct SigningAlgorithm(pub jwk::Algorithm);

impl JwsSigningAlgorithm<CoreJsonWebKeyType> for SigningAlgorithm {
    fn key_type(&self) -> Option<CoreJsonWebKeyType> {
        match self.0 {
            jwk::Algorithm::HS256 | jwk::Algorithm::HS384 | jwk::Algorithm::HS512 => {
                Some(CoreJsonWebKeyType::Symmetric)
            }
            jwk::Algorithm::RS256 | jwk::Algorithm::RS384 | jwk::Algorithm::RS512 => {
                Some(CoreJsonWebKeyType::RSA)
            }
            jwk::Algorithm::PS256
            | jwk::Algorithm::PS384
            | jwk::Algorithm::PS512
            | jwk::Algorithm::EdDSA
            | jwk::Algorithm::EdBlake2b
            | jwk::Algorithm::ES256K
            | jwk::Algorithm::ES256KR
            | jwk::Algorithm::ESKeccakKR
            | jwk::Algorithm::ESBlake2b
            | jwk::Algorithm::ESBlake2bK
            | jwk::Algorithm::AleoTestnet1Signature
            | jwk::Algorithm::ES256
            | jwk::Algorithm::ES384 => Some(CoreJsonWebKeyType::EllipticCurve),
            jwk::Algorithm::None => None,
        }
    }

    fn uses_shared_secret(&self) -> bool {
        self.key_type()
            .map(|kty| kty == CoreJsonWebKeyType::Symmetric)
            .unwrap_or(false)
    }

    fn hash_bytes(&self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        Ok(match self.0 {
            jwk::Algorithm::None => {
                return Err(
                    "signature algorithm `none` has no corresponding hash algorithm".to_string(),
                );
            }
            _ => bytes.to_vec(), // hack to do the hashing with the signing
        })
    }

    fn rsa_sha_256() -> Self {
        Self(jwk::Algorithm::RS256)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct WebKey {
    jwk: ssi::jwk::JWK,
    key_id: Option<JsonWebKeyId>,
    key_type: CoreJsonWebKeyType,
}

impl WebKey {
    fn new(jwk: JWK) -> Self {
        Self {
            jwk: jwk.clone(),
            key_id: jwk
                .key_id
                .as_ref()
                .map(|kid| JsonWebKeyId::new(kid.clone())),
            key_type: SigningAlgorithm(jwk.get_algorithm().unwrap())
                .key_type()
                .unwrap(),
        }
    }
}

impl JsonWebKey<SigningAlgorithm, CoreJsonWebKeyType, CoreJsonWebKeyUse> for WebKey {
    fn key_id(&self) -> Option<&JsonWebKeyId> {
        self.key_id.as_ref()
    }
    fn key_type(&self) -> &CoreJsonWebKeyType {
        &self.key_type
    }
    fn key_use(&self) -> Option<&CoreJsonWebKeyUse> {
        Some(&CoreJsonWebKeyUse::Signature)
    }

    fn new_symmetric(_key: Vec<u8>) -> Self {
        Self::new(jwk::JWK::from(jwk::Params::Symmetric(
            jwk::SymmetricParams { key_value: None },
        )))
    }

    fn verify_signature(
        &self,
        signature_alg: &SigningAlgorithm,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), SignatureVerificationError> {
        jws::verify_bytes(signature_alg.0, message, &self.jwk, signature)
            .map_err(|e| SignatureVerificationError::Other(e.to_string()))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct PrivateWebKey {
    jwk: ssi::jwk::JWK,
    // key_id: Option<JsonWebKeyId>,
}

impl PrivateWebKey {
    pub fn new(jwk: &JWK) -> Self {
        Self { jwk: jwk.clone() }
    }
}

impl PrivateSigningKey<SigningAlgorithm, CoreJsonWebKeyType, CoreJsonWebKeyUse, WebKey>
    for PrivateWebKey
{
    fn sign(
        &self,
        signature_alg: &SigningAlgorithm,
        message: &[u8],
    ) -> Result<Vec<u8>, SigningError> {
        jws::sign_bytes(signature_alg.0, message, &self.jwk).map_err(|_| SigningError::CryptoError)
    }

    fn as_verification_key(&self) -> WebKey {
        WebKey::new(self.jwk.to_public())
    }
}

impl AdditionalClaims for IdTokenAdditionalClaims {}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(transparent)]
pub struct IdToken(
    openidconnect::IdToken<
        IdTokenAdditionalClaims,
        CoreGenderClaim,
        CoreJweContentEncryptionAlgorithm,
        SigningAlgorithm,
        CoreJsonWebKeyType,
    >,
);

pub type IdTokenClaims = openidconnect::IdTokenClaims<IdTokenAdditionalClaims, CoreGenderClaim>;

impl IdToken {
    pub async fn claims<'a>(
        &'a self,
        verifier: &IdTokenVerifier<'_>,
        nonce_verifier: &Nonce,
    ) -> Result<&'a IdTokenClaims, ClaimsVerificationError> {
        let passthrough_verifier: InnerVerifier =
            openidconnect::IdTokenVerifier::new_insecure_without_verification();
        let claims = self.0.claims(&passthrough_verifier, nonce_verifier)?;
        let jwk = if let Some(jwk) = &claims.additional_claims().sub_jwk {
            match jwk.thumbprint() {
                Ok(t) => {
                    if t != claims.subject().as_str() {
                        return Err(ClaimsVerificationError::Other(
                            "sub does not match sub_jwk's thumbprint".to_string(),
                        ));
                    }
                }
                Err(e) => {
                    return Err(ClaimsVerificationError::Other(format!(
                        "Invalid JWK for sub_jwk: {}",
                        e
                    )))
                }
            };
            jwk.clone()
        } else {
            let vms = get_verification_methods(
                claims.subject(),
                VerificationRelationship::Authentication,
                verifier.did_resolver,
            )
            .await
            .map_err(|e| {
                ClaimsVerificationError::InvalidSubject(format!("DID resolution failed: {e}"))
            })?;
            if let Some((_, vm)) = vms.iter().find(|(_, vm)| vm.public_key_jwk.is_some()) {
                let mut jwk = vm.public_key_jwk.as_ref().unwrap().clone();
                jwk.key_id = jwk.key_id.map(|kid| {
                    // TODO would be better with a DID type
                    let sub = claims.subject().as_str();
                    if !kid.starts_with(sub) {
                        format!("{}#{}", sub, kid)
                    } else {
                        kid
                    }
                });
                jwk
            } else {
                return Err(ClaimsVerificationError::InvalidSubject(
                    "Unable to find a verification method with JWK".to_string(),
                ));
            }
        };
        self.0
            .claims(&verifier.inner_verifier(&jwk), nonce_verifier)
    }

    pub fn new(
        claims: IdTokenClaims,
        key: PrivateWebKey,
        alg: SigningAlgorithm,
    ) -> Result<Self, JsonWebTokenError> {
        Ok(Self(openidconnect::IdToken::new(
            claims, &key, alg, None, None,
        )?))
    }
}

type InnerVerifier<'a> = openidconnect::IdTokenVerifier<
    'a,
    SigningAlgorithm,
    CoreJsonWebKeyType,
    CoreJsonWebKeyUse,
    WebKey,
>;

pub struct IdTokenVerifier<'a> {
    client_id: ClientId,
    did_resolver: &'a dyn DIDResolver,
    issuer: IssuerUrl,
}

impl<'a> IdTokenVerifier<'a> {
    pub fn new(
        did_resolver: &'a dyn DIDResolver,
        client_id: ClientId,
        issuer: IssuerUrl,
    ) -> IdTokenVerifier {
        Self {
            client_id,
            did_resolver,
            issuer,
        }
    }

    fn inner_verifier(&self, jwk: &JWK) -> InnerVerifier<'a> {
        openidconnect::IdTokenVerifier::new_public_client(
            self.client_id.clone(),
            self.issuer.clone(),
            JsonWebKeySet::new(vec![WebKey::new(jwk.clone())]),
        )
        .set_allowed_algs(vec![
            SigningAlgorithm(jwk::Algorithm::ES256K),
            SigningAlgorithm(jwk::Algorithm::ES256),
            SigningAlgorithm(jwk::Algorithm::EdDSA),
        ])
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum AuthErrorResponseTypeInner {
    UserCancelled,
    RegistrationValueNotSupported,
    SubjectSyntaxTypesNotSupported,
    InvalidRegistrationUri,
    InvalidRegistrationObject,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum AuthErrorResponseType {
    Siop(AuthErrorResponseTypeInner),
    Core(CoreErrorResponseType),
}
impl ErrorResponseType for AuthErrorResponseType {}

#[cfg(test)]
pub(crate) mod tests {
    use crate::provider::ProviderDiscoveryMetadata;

    use super::*;
    use did_ion::DIDION;
    use openidconnect::ClaimsVerificationError;
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use ssi::did::DIDMethod;

    #[test]
    fn const_static_metadata() {
        let value = json!({
            "authorization_endpoint": "openid:",
            "response_types_supported": [
                "id_token"
            ],
            "scopes_supported": [
                "openid"
            ],
            "subject_types_supported": [
                "pairwise"
            ],
            "id_token_signing_alg_values_supported": [
                "ES256"
            ],
            "request_object_signing_alg_values_supported": [
                "ES256"
            ],
            "subject_syntax_types_supported": [
                "urn:ietf:params:oauth:jwk-thumbprint"
            ],
            "id_token_types_supported": [
                "subject_signed"
            ],
            "issuer": "https://self-issued.me/v2/openid",
            "jwks_uri": "https://self-issued.me/v2/not-used",
        });
        assert_eq!(
            serde_json::to_value(&ProviderDiscoveryMetadata::static_config()).unwrap(),
            value
        );
    }

    #[tokio::test]
    async fn example_id_token_jwt() {
        let value = json!("eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6aW9uOkVpQnYwVDBpUmxETC1JRDN3S3FmVHlMblpDZnhJc0c2XzhnS0hIRlZjVlF2ekE6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKemFXZHVYMGM0UW5wc2JqbE5TbEFpTENKd2RXSnNhV05MWlhsS2Qyc2lPbnNpWVd4bklqb2lSVk15TlRaTElpd2lZM0oySWpvaWMyVmpjREkxTm1zeElpd2lhMlY1WDI5d2N5STZXeUoyWlhKcFpua2lYU3dpYTJsa0lqb2ljMmxuYmw5SE9FSjZiRzQ1VFVwUUlpd2lhM1I1SWpvaVJVTWlMQ0oxYzJVaU9pSnphV2NpTENKNElqb2ljMGN4VkRKQ1dtSnlRMDF4VURGUGF6bE1VbVpsZHpsRFFWUjFSMGswWDJOQk0xbzFVWEpEVlVSc05DSXNJbmtpT2lKRlRIVm9NMFp0TjFSU2MwbHpVR0l5VlVORldXWklNM0UwUkc5M1VVd3hTa1J0TkRoZk5GRnROR05GSW4wc0luQjFjbkJ2YzJWeklqcGJJbUYxZEdobGJuUnBZMkYwYVc5dUlsMHNJblI1Y0dVaU9pSkZZMlJ6WVZObFkzQXlOVFpyTVZabGNtbG1hV05oZEdsdmJrdGxlVEl3TVRraWZWMHNJbk5sY25acFkyVnpJanBiWFgxOVhTd2lkWEJrWVhSbFEyOXRiV2wwYldWdWRDSTZJa1ZwUkU5aGRtbEthVzl0WlU4dGVWWnBlRkZNZEd4eE1GaEhWbTlEVG10alN6VTNialpLY1c5WlNtdFRSRkVpZlN3aWMzVm1abWw0UkdGMFlTSTZleUprWld4MFlVaGhjMmdpT2lKRmFVSlpVV3hoWkhweWRUSjJUWHBwTUVKc1UxVkNNRnBvYjI0MGJIVXpSRlY1Y0dWRVlraEdTazU2UmxaM0lpd2ljbVZqYjNabGNubERiMjF0YVhSdFpXNTBJam9pUldsQ2JHMWxjRm8yVld0VFJ6TkNTMWxzVUdnM2RYTkhkRzFYYUV4blRWWm5UMFpCTUdkbloyUklTM1JtZHlKOWZRI3NpZ25fRzhCemxuOU1KUCJ9.eyJpYXQiOjE2Njc4MTAzNDksIm5vbmNlIjoidkxzQUF6YWNmZGRQUVo4NSIsInN1YiI6ImRpZDppb246RWlCdjBUMGlSbERMLUlEM3dLcWZUeUxuWkNmeElzRzZfOGdLSEhGVmNWUXZ6QTpleUprWld4MFlTSTZleUp3WVhSamFHVnpJanBiZXlKaFkzUnBiMjRpT2lKeVpYQnNZV05sSWl3aVpHOWpkVzFsYm5RaU9uc2ljSFZpYkdsalMyVjVjeUk2VzNzaWFXUWlPaUp6YVdkdVgwYzRRbnBzYmpsTlNsQWlMQ0p3ZFdKc2FXTkxaWGxLZDJzaU9uc2lZV3huSWpvaVJWTXlOVFpMSWl3aVkzSjJJam9pYzJWamNESTFObXN4SWl3aWEyVjVYMjl3Y3lJNld5SjJaWEpwWm5raVhTd2lhMmxrSWpvaWMybG5ibDlIT0VKNmJHNDVUVXBRSWl3aWEzUjVJam9pUlVNaUxDSjFjMlVpT2lKemFXY2lMQ0o0SWpvaWMwY3hWREpDV21KeVEwMXhVREZQYXpsTVVtWmxkemxEUVZSMVIwazBYMk5CTTFvMVVYSkRWVVJzTkNJc0lua2lPaUpGVEhWb00wWnROMVJTYzBselVHSXlWVU5GV1daSU0zRTBSRzkzVVV3eFNrUnRORGhmTkZGdE5HTkZJbjBzSW5CMWNuQnZjMlZ6SWpwYkltRjFkR2hsYm5ScFkyRjBhVzl1SWwwc0luUjVjR1VpT2lKRlkyUnpZVk5sWTNBeU5UWnJNVlpsY21sbWFXTmhkR2x2Ymt0bGVUSXdNVGtpZlYwc0luTmxjblpwWTJWeklqcGJYWDE5WFN3aWRYQmtZWFJsUTI5dGJXbDBiV1Z1ZENJNklrVnBSRTloZG1sS2FXOXRaVTh0ZVZacGVGRk1kR3h4TUZoSFZtOURUbXRqU3pVM2JqWktjVzlaU210VFJGRWlmU3dpYzNWbVptbDRSR0YwWVNJNmV5SmtaV3gwWVVoaGMyZ2lPaUpGYVVKWlVXeGhaSHB5ZFRKMlRYcHBNRUpzVTFWQ01GcG9iMjQwYkhVelJGVjVjR1ZFWWtoR1NrNTZSbFozSWl3aWNtVmpiM1psY25sRGIyMXRhWFJ0Wlc1MElqb2lSV2xDYkcxbGNGbzJWV3RUUnpOQ1MxbHNVR2czZFhOSGRHMVhhRXhuVFZablQwWkJNR2RuWjJSSVMzUm1keUo5ZlEiLCJleHAiOjE2Njc4MTMzNDksImF1ZCI6ImRpZDp3ZWI6YXBpLnZwLmludGVyb3Auc3BydWNlaWQueHl6IiwiX3ZwX3Rva2VuIjp7InByZXNlbnRhdGlvbl9zdWJtaXNzaW9uIjp7ImlkIjoiRUE2RkY2NjItREM1Mi00RUZFLTk1QzUtMEVCOTY0MDdBNEM5IiwiZGVmaW5pdGlvbl9pZCI6ImU3NWVjZjY0LTZkZDEtNGZiNC1iMDcwLTY1MzU4ZTExMmQxMSIsImRlc2NyaXB0b3JfbWFwIjpbeyJwYXRoIjoiJCIsImlkIjoiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJmb3JtYXQiOiJqd3RfdnAiLCJwYXRoX25lc3RlZCI6eyJpZCI6IlZlcmlmaWFibGVDcmVkZW50aWFsIiwiZm9ybWF0Ijoiand0X3ZjIiwicGF0aCI6IiQudmVyaWZpYWJsZUNyZWRlbnRpYWxbMF0ifX1dfX0sImlzcyI6Imh0dHBzOlwvXC9zZWxmLWlzc3VlZC5tZVwvdjJcL29wZW5pZC12YyJ9.gv-4MBCe7ws4iCx_aRC3MdlVMLk6O5dDCoaTwExsc_IOebHP6InfNYtICYrzntO2F85jZu-5hEdSo3PF9XVInA");
        let id_token = serde_json::from_value::<IdToken>(value).unwrap();
        let ion: DIDION = DIDION::new(Some(
            "https://beta.discover.did.microsoft.com/1.0/".to_string(),
        ));
        let verifier = IdTokenVerifier::new(
            ion.to_resolver(),
            ClientId::new("did:web:api.vp.interop.spruceid.xyz".to_string()),
            IssuerUrl::new("https://self-issued.me/v2/openid-vc".to_string()).unwrap(),
        );
        let nonce = Nonce::new("vLsAAzacfddPQZ85".to_string());
        let claims = id_token.claims(&verifier, &nonce);
        match claims.await {
            Err(ClaimsVerificationError::Expired(e)) => {
                assert!(e.contains("ID token expired at 2022-11-07 09:29:09 UTC"))
            }
            _ => panic!(),
        }
    }

    #[tokio::test]
    async fn id_token_jwt_2() {
        let value = json!("eyJraWQiOiJkaWQ6aW9uOkVpQTZkWlV2SFlhWWtFWENMV2Y4aDdIR0d0T3M0OEsxV18xMGZtS2x2cXNSbkE6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKclpYa3RNU0lzSW5CMVlteHBZMHRsZVVwM2F5STZleUpqY25ZaU9pSkZaREkxTlRFNUlpd2lhM1I1SWpvaVQwdFFJaXdpZUNJNklsRTNlRlJJZURreFpXMW1iMjR5VW1NdFJtbGFhWEZqV0RocGNEazVWamhrYzBwck1YaE5Na04wYUVraUxDSnJhV1FpT2lKclpYa3RNU0o5TENKd2RYSndiM05sY3lJNld5SmhkWFJvWlc1MGFXTmhkR2x2YmlKZExDSjBlWEJsSWpvaVNuTnZibGRsWWt0bGVUSXdNakFpZlYxOWZWMHNJblZ3WkdGMFpVTnZiVzFwZEcxbGJuUWlPaUpGYVVJeWVVRjRabkJFYm5wM1ZUQmlRMXBTU1RKbE9XdFBSMUpwZEVSNmFHTlhhRVpvUnpkSFNqZHpRVTVuSW4wc0luTjFabVpwZUVSaGRHRWlPbnNpWkdWc2RHRklZWE5vSWpvaVJXbEVWa0ptVWxBMVUyWm5ZV3RrWVRsUlltUm1PR0k0V1RWUU9ETjNOR2swUnkxblEyZHdPUzB3ZFRoRFp5SXNJbkpsWTI5MlpYSjVRMjl0YldsMGJXVnVkQ0k2SWtWcFFrOVFiVVF4TlVscE5HeGxOVGRYU0d0UVZ6ZG5SM05sZG5CQ1pXbGFkVmhUTkZKdk5WVnNkRGhLVTNjaWZYMCNrZXktMSIsImFsZyI6IkVkRFNBIn0.eyJzdWIiOiJkaWQ6aW9uOkVpQTZkWlV2SFlhWWtFWENMV2Y4aDdIR0d0T3M0OEsxV18xMGZtS2x2cXNSbkE6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKclpYa3RNU0lzSW5CMVlteHBZMHRsZVVwM2F5STZleUpqY25ZaU9pSkZaREkxTlRFNUlpd2lhM1I1SWpvaVQwdFFJaXdpZUNJNklsRTNlRlJJZURreFpXMW1iMjR5VW1NdFJtbGFhWEZqV0RocGNEazVWamhrYzBwck1YaE5Na04wYUVraUxDSnJhV1FpT2lKclpYa3RNU0o5TENKd2RYSndiM05sY3lJNld5SmhkWFJvWlc1MGFXTmhkR2x2YmlKZExDSjBlWEJsSWpvaVNuTnZibGRsWWt0bGVUSXdNakFpZlYxOWZWMHNJblZ3WkdGMFpVTnZiVzFwZEcxbGJuUWlPaUpGYVVJeWVVRjRabkJFYm5wM1ZUQmlRMXBTU1RKbE9XdFBSMUpwZEVSNmFHTlhhRVpvUnpkSFNqZHpRVTVuSW4wc0luTjFabVpwZUVSaGRHRWlPbnNpWkdWc2RHRklZWE5vSWpvaVJXbEVWa0ptVWxBMVUyWm5ZV3RrWVRsUlltUm1PR0k0V1RWUU9ETjNOR2swUnkxblEyZHdPUzB3ZFRoRFp5SXNJbkpsWTI5MlpYSjVRMjl0YldsMGJXVnVkQ0k2SWtWcFFrOVFiVVF4TlVscE5HeGxOVGRYU0d0UVZ6ZG5SM05sZG5CQ1pXbGFkVmhUTkZKdk5WVnNkRGhLVTNjaWZYMCIsImF1ZCI6ImRpZDppb246RWlEWFJFNkdQcDcxNkdadng0MDRMRnlnUW9Xc2hpSXFoT0ZORkJacW9adEQzZzpleUprWld4MFlTSTZleUp3WVhSamFHVnpJanBiZXlKaFkzUnBiMjRpT2lKeVpYQnNZV05sSWl3aVpHOWpkVzFsYm5RaU9uc2ljSFZpYkdsalMyVjVjeUk2VzNzaWFXUWlPaUpyWlhrdE1TSXNJbkIxWW14cFkwdGxlVXAzYXlJNmV5SmpjbllpT2lKRlpESTFOVEU1SWl3aWEzUjVJam9pVDB0UUlpd2llQ0k2SWtGek1YTlhkM1JzVEhkUlVUZ3dNRWxMZEMwMGFFWlRNWFJLY1Y5amVEQmtTR0ZtT0RKVVRUSk1XVVVpTENKcmFXUWlPaUpyWlhrdE1TSjlMQ0p3ZFhKd2IzTmxjeUk2V3lKaGRYUm9aVzUwYVdOaGRHbHZiaUpkTENKMGVYQmxJam9pU25OdmJsZGxZa3RsZVRJd01qQWlmVjE5ZlYwc0luVndaR0YwWlVOdmJXMXBkRzFsYm5RaU9pSkZhVUpSV0hCcVNrOXZRMGRwVkZwNk5WZDNaa0UzWTNCcU56RmFlRzlaVVRRMGNqSTFTMU5HU0VGdFpIRlJJbjBzSW5OMVptWnBlRVJoZEdFaU9uc2laR1ZzZEdGSVlYTm9Jam9pUldsRGNFdDZjRWRyV2xOYWRuUlZNRzFFVEUxUVpVWlNOSEo0U3pscmFsSlZhV0ZMZW5sdVozSlpkMnhWWnlJc0luSmxZMjkyWlhKNVEyOXRiV2wwYldWdWRDSTZJa1ZwUTNOZlFqVkhkRWN6ZW1SNFZtOXdOVGR4V2xSamIzQXpNVlJEUkRGdVZGVlhXbXhmVkZKNVZYbE1ObmNpZlgwIiwiaXNzIjoiaHR0cHM6XC9cL3NlbGYtaXNzdWVkLm1lXC92Mlwvb3BlbmlkLXZjIiwiZXhwIjoxNjY2MjE1MDc4LCJpYXQiOjE2NjYyMDA2NzgsIm5vbmNlIjoiYmNjZWIzNDctMTM3NC00OWI4LWFjZTAtYjg2ODE2MmMxMjJkIiwianRpIjoiNTFlNzQ4YmMtMzI5Yy00YmRhLTkxNjUtYzIwZjY2YmRjMmE5IiwiX3ZwX3Rva2VuIjp7InByZXNlbnRhdGlvbl9zdWJtaXNzaW9uIjp7ImlkIjoiMWY4NzVjNmQtZjk3Yy00NGJlLThhOGYtMmNhMmU1OWNjNDg1IiwiZGVmaW5pdGlvbl9pZCI6IjgwMDZiNWZiLTZlM2ItNDJkMS1hMmJlLTU1ZWQyYTA4MDczZCIsImRlc2NyaXB0b3JfbWFwIjpbeyJpZCI6IlZlcmlmaWVkRW1wbG95ZWVWQyIsImZvcm1hdCI6Imp3dF92cCIsInBhdGgiOiIkIiwicGF0aF9uZXN0ZWQiOnsiaWQiOiJWZXJpZmllZEVtcGxveWVlVkMiLCJmb3JtYXQiOiJqd3RfdmMiLCJwYXRoIjoiJC52ZXJpZmlhYmxlQ3JlZGVudGlhbFswXSJ9fV19fX0._OhVfVklwXPBDFJ9d2f9BBMPzpFGfjJ6zEgMBehgWkyBn_PUyvb_GzQHnrKfAsi2TC0AM-ueHWcVgtqeQxI0Ag");
        let id_token = serde_json::from_value::<IdToken>(value).unwrap();
        let ion: DIDION = DIDION::new(Some(
            "https://beta.discover.did.microsoft.com/1.0/".to_string(),
        ));
        let verifier = IdTokenVerifier::new(ion.to_resolver(), ClientId::new("did:ion:EiDXRE6GPp716GZvx404LFygQoWshiIqhOFNFBZqoZtD3g:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJrZXktMSIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IkFzMXNXd3RsTHdRUTgwMElLdC00aEZTMXRKcV9jeDBkSGFmODJUTTJMWUUiLCJraWQiOiJrZXktMSJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUJRWHBqSk9vQ0dpVFp6NVd3ZkE3Y3BqNzFaeG9ZUTQ0cjI1S1NGSEFtZHFRIn0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlDcEt6cEdrWlNadnRVMG1ETE1QZUZSNHJ4SzlralJVaWFLenluZ3JZd2xVZyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQ3NfQjVHdEczemR4Vm9wNTdxWlRjb3AzMVRDRDFuVFVXWmxfVFJ5VXlMNncifX0".to_string()),
        IssuerUrl::new("https://self-issued.me/v2/openid-vc".to_string()).unwrap(),
        );
        let nonce = Nonce::new("vLsAAzacfddPQZ85".to_string());
        let claims = id_token.claims(&verifier, &nonce);
        match claims.await {
            Err(ClaimsVerificationError::Expired(e)) => {
                assert!(e.contains("ID token expired at 2022-10-19 21:31:18 UTC"))
            }
            _ => panic!(),
        }
    }
}

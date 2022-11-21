use openidconnect::{
    core::{
        CoreAuthDisplay, CoreClaimName, CoreClaimType, CoreClientAuthMethod, CoreGrantType,
        CoreJsonWebKeyType, CoreJsonWebKeyUse, CoreJweContentEncryptionAlgorithm,
        CoreJweKeyManagementAlgorithm, CoreResponseMode, CoreResponseType,
        CoreSubjectIdentifierType,
    },
    AdditionalProviderMetadata, AuthUrl, IssuerUrl, JsonWebKeySetUrl, ProviderMetadata,
    ResponseTypes, Scope,
};
use serde::{Deserialize, Serialize};
use ssi::jwk;

use crate::{IdTokenType, SigningAlgorithm, WebKey};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProviderDiscoveryAdditionalMetadata {
    subject_syntax_types_supported: Vec<String>,
    id_token_types_supported: Vec<IdTokenType>,
}

impl AdditionalProviderMetadata for ProviderDiscoveryAdditionalMetadata {}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProviderDiscoveryMetadata(
    pub  ProviderMetadata<
        ProviderDiscoveryAdditionalMetadata,
        CoreAuthDisplay,
        CoreClientAuthMethod,
        CoreClaimName,
        CoreClaimType,
        CoreGrantType,
        CoreJweContentEncryptionAlgorithm,
        CoreJweKeyManagementAlgorithm,
        SigningAlgorithm,
        CoreJsonWebKeyType,
        CoreJsonWebKeyUse,
        WebKey,
        CoreResponseMode,
        CoreResponseType,
        CoreSubjectIdentifierType,
    >,
);

impl ProviderDiscoveryMetadata {
    pub fn static_config() -> Self {
        Self(
            ProviderMetadata::new(
                IssuerUrl::new("https://self-issued.me/v2/openid".to_string()).unwrap(), // TODO
                AuthUrl::new("openid:".to_string()).unwrap(),
                JsonWebKeySetUrl::new("https://self-issued.me/v2/not-used".to_string()).unwrap(), // TODO
                vec![ResponseTypes::new(vec![CoreResponseType::IdToken])],
                vec![CoreSubjectIdentifierType::Pairwise],
                vec![SigningAlgorithm(jwk::Algorithm::ES256)],
                ProviderDiscoveryAdditionalMetadata {
                    subject_syntax_types_supported: vec![
                        "urn:ietf:params:oauth:jwk-thumbprint".to_string()
                    ],
                    id_token_types_supported: vec![IdTokenType::SubjectSigned],
                },
            )
            .set_scopes_supported(Some(vec![Scope::new("openid".to_string())]))
            .set_request_object_signing_alg_values_supported(Some(vec![SigningAlgorithm(
                jwk::Algorithm::ES256,
            )])),
        )
    }
}

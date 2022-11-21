use openidconnect::{
    core::{
        CoreApplicationType, CoreClientAuthMethod, CoreGrantType, CoreJsonWebKeyType,
        CoreJsonWebKeyUse, CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm,
        CoreRegisterErrorResponseType, CoreResponseMode, CoreResponseType,
        CoreSubjectIdentifierType,
    },
    registration::{
        AdditionalClientMetadata, ClientMetadata, ClientRegistrationRequest,
        ClientRegistrationResponse, EmptyAdditionalClientRegistrationResponse,
    },
    ClientId, Nonce, RedirectUrl, Scope,
};
use serde::{Deserialize, Serialize};

use crate::{SigningAlgorithm, WebKey};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RequestParameters {
    pub scope: Scope,
    pub response_type: CoreResponseType,
    pub response_mode: CoreResponseMode,
    pub client_id: ClientId, // DIDURL, // TODO should just be a DID but it's private in ssi
    pub redirect_uri: RedirectUrl,
    pub nonce: Nonce,
}
impl AdditionalClientMetadata for RequestParameters {}

impl RequestParameters {
    pub fn new(client_id: ClientId, redirect_uri: RedirectUrl, nonce: Nonce) -> Self {
        Self {
            scope: Scope::new("openid".to_string()),
            response_type: CoreResponseType::IdToken,
            response_mode: CoreResponseMode::Extension("post".to_string()),
            client_id,
            redirect_uri,
            nonce,
        }
    }
}

pub struct RPMetadata(
    ClientMetadata<
        RequestParameters,
        CoreApplicationType,
        CoreClientAuthMethod,
        CoreGrantType,
        CoreJweContentEncryptionAlgorithm,
        CoreJweKeyManagementAlgorithm,
        SigningAlgorithm,
        CoreJsonWebKeyType,
        CoreJsonWebKeyUse,
        WebKey,
        CoreResponseType,
        CoreSubjectIdentifierType,
    >,
);

impl RPMetadata {
    fn new(client_id: ClientId, redirect_uri: RedirectUrl) -> Self {
        Self(ClientMetadata::new(
            vec![],
            RequestParameters::new(client_id, redirect_uri, Nonce::new_random()),
        ))
    }
}

pub struct RPRegistrationResponse(
    ClientRegistrationResponse<
        RequestParameters,
        EmptyAdditionalClientRegistrationResponse,
        CoreApplicationType,
        CoreClientAuthMethod,
        CoreGrantType,
        CoreJweContentEncryptionAlgorithm,
        CoreJweKeyManagementAlgorithm,
        SigningAlgorithm,
        CoreJsonWebKeyType,
        CoreJsonWebKeyUse,
        WebKey,
        CoreResponseType,
        CoreSubjectIdentifierType,
    >,
);

impl RPRegistrationResponse {
    fn new(client_id: ClientId, redirect_uri: RedirectUrl) -> Self {
        Self(ClientRegistrationResponse::new(
            client_id.clone(),
            vec![],
            RequestParameters::new(client_id, redirect_uri, Nonce::new_random()),
            EmptyAdditionalClientRegistrationResponse {},
        ))
    }
}

pub struct RPRegistrationRequest(
    ClientRegistrationRequest<
        RequestParameters,
        EmptyAdditionalClientRegistrationResponse,
        CoreApplicationType,
        CoreClientAuthMethod,
        CoreRegisterErrorResponseType,
        CoreGrantType,
        CoreJweContentEncryptionAlgorithm,
        CoreJweKeyManagementAlgorithm,
        SigningAlgorithm,
        CoreJsonWebKeyType,
        CoreJsonWebKeyUse,
        WebKey,
        CoreResponseType,
        CoreSubjectIdentifierType,
    >,
);

impl RPRegistrationRequest {
    fn new(client_id: ClientId, redirect_uri: RedirectUrl) -> Self {
        Self(ClientRegistrationRequest::new(
            vec![],
            RequestParameters::new(client_id, redirect_uri, Nonce::new_random()),
        ))
    }
}

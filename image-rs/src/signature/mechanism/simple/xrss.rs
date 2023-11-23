// Copyright (c) 2023 IBM Corp.
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use base64::Engine;
use oci_distribution::{
    secrets::RegistryAuth,
    RegistryOperation,
    Reference,
};
use reqwest::{header::HeaderValue, Client};
use serde::*;

use crate::signature::image::{digest::Digest, Image};

#[derive(Debug, Default)]
pub struct RegistryClient {
    // reqwest client for the container registry that supports the X-R-S-S extension
    pub client: Client,
}

#[derive(Deserialize, Debug, PartialEq, Eq, Serialize, Default)]
pub struct GetOAuthTokenResponse {
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub access_token: String,
    #[serde(default)]
    pub expires_in: u32,
    #[serde(default)]
    pub issued_at: String,
}

#[derive(Deserialize, Debug, PartialEq, Eq, Serialize, Default)]
pub struct GetSignaturesResponse {
    #[serde(default)]
    signatures: Vec<RegistrySignature>,
}

#[derive(Deserialize, Debug, PartialEq, Eq, Serialize, Default)]
pub struct RegistrySignature {
    #[serde(default, rename = "schemaVersion")]
    pub schema_version: u32,
    #[serde(default)]
    pub name: String,
    #[serde(default, rename = "type")]
    pub signature_type: String,
    #[serde(default)]
    pub content: String,
}

impl RegistryClient {
    pub fn new() -> RegistryClient {
        RegistryClient {
            client: reqwest::Client::new(),
        }
    }

    async fn get_oauth_token_for_registry(
        &self,
        image: &Image,
        auth: &RegistryAuth,
    ) -> Result<String> {
        match auth {
            RegistryAuth::Anonymous => {
                bail!("Trying to get signature from a registry without providing auth information")
            }
            RegistryAuth::Basic(_username, _password) => {
                let mut oci_distribution_client = oci_distribution::client::Client::default();
                let auth_token = oci_distribution_client
                    .auth(&image.reference, auth, RegistryOperation::Pull)
                    .await
                    .context("Failed to authenticate with the registry")?;
                if auth_token.is_none() {
                    bail!("Authenticating with the registry did not return an oauth token");
                }

                Ok(auth_token.unwrap())
            }
        }
    }

    pub async fn get_signatures_from_registry(
        &self,
        image: &Image,
        digest: &Digest,
        auth: &RegistryAuth,
    ) -> Result<Vec<Vec<u8>>> {
        let mut sigs: Vec<Vec<u8>> = Vec::new();

        let res = self
            .client
            .get(format!("https://{}/v2/", image.reference.registry()))
            .send()
            .await
            .context("Failed to query extensions supported by registry v2 endpoint")?;

        if res.headers().get("x-registry-supports-signatures")
            == Some(&HeaderValue::from_static("1"))
        {
            let oauth_token = self.get_oauth_token_for_registry(image, auth).await?;
            let res = self
                .client
                .get(format_registry_signatures_extension_url(
                    &image.reference,
                    digest,
                ))
                .bearer_auth(oauth_token)
                .send()
                .await
                .context("Failed to get signatures from registry")?;

            let signatures_response_body: GetSignaturesResponse = res
                .json::<GetSignaturesResponse>()
                .await
                .context("Unexpected response from fetching signatures from registry")?;

            for registry_signature in signatures_response_body.signatures.iter() {
                let signature = base64::engine::general_purpose::STANDARD.decode(&registry_signature.content).context(
                        "Error when decoding sognature from registry. Signature is not base64 encoded"
                )?;
                sigs.push(signature);
            }
        }

        Ok(sigs)
    }
}

fn format_registry_signatures_extension_url(image_ref: &Reference, digest: &Digest) -> String {
    format!(
        "https://{}/extensions/v2/{}/signatures/{}:{}",
        image_ref.registry(),
        image_ref.repository(),
        digest.algorithm(),
        digest.value()
    )
}

// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod auth_config;

use std::{collections::HashMap, fs::File, io::BufReader, path::Path, sync::Arc};

use anyhow::*;
use oci_distribution::{secrets::RegistryAuth, Reference};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::secure_channel::SecureChannel;

/// The reason for using the `/run` directory here is that in general HW-TEE,
/// the `/run` directory is mounted in `tmpfs`, which is located in the encrypted memory protected by HW-TEE.
/// [`AUTH_FILE_PATH`] shows the path to the `auth.json` file.
pub const AUTH_FILE_PATH: &str = "/run/image-security/auth.json";

/// Hard-coded ResourceDescription of `auth.json`.
pub const RESOURCE_DESCRIPTION: &str = "Credential";

#[derive(Deserialize, Serialize)]
pub struct DockerConfigFile {
    auths: HashMap<String, DockerAuthConfig>,
    // TODO: support credential helpers
}

#[derive(Deserialize, Serialize)]
pub struct DockerAuthConfig {
    auth: String,
}

/// Get a credential (RegistryAuth) for the given Reference.
/// First, it will try to find auth info in the local
/// `auth.json`. If there is not one, it will
/// ask one from the [`SecureChannel`], which connects
/// to the GetResource API of Attestation Agent.
/// Then, it will use the `auth.json` to find
/// a credential of the given image reference.
pub async fn credential_for_reference(
    reference: &Reference,
    secure_channel: Arc<Mutex<SecureChannel>>,
) -> Result<RegistryAuth> {
    // if Policy config file does not exist, get if from KBS.
    if !Path::new(AUTH_FILE_PATH).exists() {
        secure_channel
            .lock()
            .await
            .get_resource(RESOURCE_DESCRIPTION, HashMap::new(), AUTH_FILE_PATH)
            .await?;
    }

    let reader = File::open(AUTH_FILE_PATH)?;
    let buf_reader = BufReader::new(reader);
    let config: DockerConfigFile = serde_json::from_reader(buf_reader)?;

    // TODO: support credential helpers
    auth_config::credential_from_auth_config(reference, &config.auths)
}

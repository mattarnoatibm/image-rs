// This file is generated by ttrpc-compiler 0.6.1. Do not edit
// @generated

// https://github.com/Manishearth/rust-clippy/issues/702
#![allow(unknown_lints)]
#![allow(clipto_camel_casepy)]

#![cfg_attr(rustfmt, rustfmt_skip)]

#![allow(box_pointers)]
#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unsafe_code)]
#![allow(unused_imports)]
#![allow(unused_results)]
use protobuf::{CodedInputStream, CodedOutputStream, Message};
use std::collections::HashMap;
use std::sync::Arc;
use async_trait::async_trait;

#[derive(Clone)]
pub struct SealedSecretServiceClient {
    client: ::ttrpc::r#async::Client,
}

impl SealedSecretServiceClient {
    pub fn new(client: ::ttrpc::r#async::Client) -> Self {
        SealedSecretServiceClient {
            client,
        }
    }

    pub async fn unseal_secret(&self, ctx: ttrpc::context::Context, req: &super::api::UnsealSecretInput) -> ::ttrpc::Result<super::api::UnsealSecretOutput> {
        let mut cres = super::api::UnsealSecretOutput::new();
        ::ttrpc::async_client_request!(self, ctx, req, "api.SealedSecretService", "UnsealSecret", cres);
    }
}

struct UnsealSecretMethod {
    service: Arc<Box<dyn SealedSecretService + Send + Sync>>,
}

#[async_trait]
impl ::ttrpc::r#async::MethodHandler for UnsealSecretMethod {
    async fn handler(&self, ctx: ::ttrpc::r#async::TtrpcContext, req: ::ttrpc::Request) -> ::ttrpc::Result<::ttrpc::Response> {
        ::ttrpc::async_request_handler!(self, ctx, req, api, UnsealSecretInput, unseal_secret);
    }
}

#[async_trait]
pub trait SealedSecretService: Sync {
    async fn unseal_secret(&self, _ctx: &::ttrpc::r#async::TtrpcContext, _: super::api::UnsealSecretInput) -> ::ttrpc::Result<super::api::UnsealSecretOutput> {
        Err(::ttrpc::Error::RpcStatus(::ttrpc::get_status(::ttrpc::Code::NOT_FOUND, "/api.SealedSecretService/UnsealSecret is not supported".to_string())))
    }
}

pub fn create_sealed_secret_service(service: Arc<Box<dyn SealedSecretService + Send + Sync>>) -> HashMap<String, ::ttrpc::r#async::Service> {
    let mut ret = HashMap::new();
    let mut methods = HashMap::new();
    let streams = HashMap::new();

    methods.insert("UnsealSecret".to_string(),
                    Box::new(UnsealSecretMethod{service: service.clone()}) as Box<dyn ::ttrpc::r#async::MethodHandler + Send + Sync>);

    ret.insert("api.SealedSecretService".to_string(), ::ttrpc::r#async::Service{ methods, streams });
    ret
}

#[derive(Clone)]
pub struct GetResourceServiceClient {
    client: ::ttrpc::r#async::Client,
}

impl GetResourceServiceClient {
    pub fn new(client: ::ttrpc::r#async::Client) -> Self {
        GetResourceServiceClient {
            client,
        }
    }

    pub async fn get_resource(&self, ctx: ttrpc::context::Context, req: &super::api::GetResourceRequest) -> ::ttrpc::Result<super::api::GetResourceResponse> {
        let mut cres = super::api::GetResourceResponse::new();
        ::ttrpc::async_client_request!(self, ctx, req, "api.GetResourceService", "GetResource", cres);
    }
}

struct GetResourceMethod {
    service: Arc<Box<dyn GetResourceService + Send + Sync>>,
}

#[async_trait]
impl ::ttrpc::r#async::MethodHandler for GetResourceMethod {
    async fn handler(&self, ctx: ::ttrpc::r#async::TtrpcContext, req: ::ttrpc::Request) -> ::ttrpc::Result<::ttrpc::Response> {
        ::ttrpc::async_request_handler!(self, ctx, req, api, GetResourceRequest, get_resource);
    }
}

#[async_trait]
pub trait GetResourceService: Sync {
    async fn get_resource(&self, _ctx: &::ttrpc::r#async::TtrpcContext, _: super::api::GetResourceRequest) -> ::ttrpc::Result<super::api::GetResourceResponse> {
        Err(::ttrpc::Error::RpcStatus(::ttrpc::get_status(::ttrpc::Code::NOT_FOUND, "/api.GetResourceService/GetResource is not supported".to_string())))
    }
}

pub fn create_get_resource_service(service: Arc<Box<dyn GetResourceService + Send + Sync>>) -> HashMap<String, ::ttrpc::r#async::Service> {
    let mut ret = HashMap::new();
    let mut methods = HashMap::new();
    let streams = HashMap::new();

    methods.insert("GetResource".to_string(),
                    Box::new(GetResourceMethod{service: service.clone()}) as Box<dyn ::ttrpc::r#async::MethodHandler + Send + Sync>);

    ret.insert("api.GetResourceService".to_string(), ::ttrpc::r#async::Service{ methods, streams });
    ret
}

#[derive(Clone)]
pub struct KeyProviderServiceClient {
    client: ::ttrpc::r#async::Client,
}

impl KeyProviderServiceClient {
    pub fn new(client: ::ttrpc::r#async::Client) -> Self {
        KeyProviderServiceClient {
            client,
        }
    }

    pub async fn un_wrap_key(&self, ctx: ttrpc::context::Context, req: &super::api::KeyProviderKeyWrapProtocolInput) -> ::ttrpc::Result<super::api::KeyProviderKeyWrapProtocolOutput> {
        let mut cres = super::api::KeyProviderKeyWrapProtocolOutput::new();
        ::ttrpc::async_client_request!(self, ctx, req, "api.KeyProviderService", "UnWrapKey", cres);
    }
}

struct UnWrapKeyMethod {
    service: Arc<Box<dyn KeyProviderService + Send + Sync>>,
}

#[async_trait]
impl ::ttrpc::r#async::MethodHandler for UnWrapKeyMethod {
    async fn handler(&self, ctx: ::ttrpc::r#async::TtrpcContext, req: ::ttrpc::Request) -> ::ttrpc::Result<::ttrpc::Response> {
        ::ttrpc::async_request_handler!(self, ctx, req, api, KeyProviderKeyWrapProtocolInput, un_wrap_key);
    }
}

#[async_trait]
pub trait KeyProviderService: Sync {
    async fn un_wrap_key(&self, _ctx: &::ttrpc::r#async::TtrpcContext, _: super::api::KeyProviderKeyWrapProtocolInput) -> ::ttrpc::Result<super::api::KeyProviderKeyWrapProtocolOutput> {
        Err(::ttrpc::Error::RpcStatus(::ttrpc::get_status(::ttrpc::Code::NOT_FOUND, "/api.KeyProviderService/UnWrapKey is not supported".to_string())))
    }
}

pub fn create_key_provider_service(service: Arc<Box<dyn KeyProviderService + Send + Sync>>) -> HashMap<String, ::ttrpc::r#async::Service> {
    let mut ret = HashMap::new();
    let mut methods = HashMap::new();
    let streams = HashMap::new();

    methods.insert("UnWrapKey".to_string(),
                    Box::new(UnWrapKeyMethod{service: service.clone()}) as Box<dyn ::ttrpc::r#async::MethodHandler + Send + Sync>);

    ret.insert("api.KeyProviderService".to_string(), ::ttrpc::r#async::Service{ methods, streams });
    ret
}

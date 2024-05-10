// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

use consensus_config::{AuthorityIndex, NetworkKeyPair};
use fastcrypto::ed25519::Ed25519PublicKey;
use tokio_rustls::rustls::{Certificate, ClientConfig, ServerConfig};

use crate::context::Context;

pub(crate) fn create_rustls_server_config(
    context: &Context,
    network_keypair: NetworkKeyPair,
) -> ServerConfig {
    let allower = AllowedPublicKeys::new(context);
    let verifier = sui_tls::ClientCertVerifier::new(allower, certificate_server_name(context));
    // TODO: refactor to use key bytes
    let self_signed_cert = sui_tls::SelfSignedCertificate::new(
        network_keypair.private_key().into_inner(),
        &certificate_server_name(context),
    );
    let tls_cert = self_signed_cert.rustls_certificate();
    let tls_private_key = self_signed_cert.rustls_private_key();
    let mut tls_config = verifier
        .rustls_server_config(vec![tls_cert], tls_private_key)
        .unwrap_or_else(|e| panic!("Failed to create TLS server config: {:?}", e));
    tls_config.alpn_protocols = vec![b"h2".to_vec()];
    tls_config
}

pub(crate) fn create_rustls_client_config(
    context: &Context,
    network_keypair: NetworkKeyPair,
    target: AuthorityIndex,
) -> ClientConfig {
    let target_public_key = context
        .committee
        .authority(target)
        .network_key
        .clone()
        .into_inner();
    let self_signed_cert = sui_tls::SelfSignedCertificate::new(
        network_keypair.private_key().into_inner(),
        &certificate_server_name(context),
    );
    let tls_cert = self_signed_cert.rustls_certificate();
    let tls_private_key = self_signed_cert.rustls_private_key();
    let mut tls_config =
        sui_tls::ServerCertVerifier::new(target_public_key, certificate_server_name(context))
            .rustls_client_config(vec![tls_cert], tls_private_key)
            .unwrap_or_else(|e| panic!("Failed to create TLS client config: {:?}", e));
    tls_config.alpn_protocols = vec![b"h2".to_vec()];
    tls_config
}

// Checks if the public key from a TLS certificate belongs to one of the validators.
struct AllowedPublicKeys {
    // TODO: refactor to use key bytes
    keys: BTreeSet<Ed25519PublicKey>,
}

impl AllowedPublicKeys {
    fn new(context: &Context) -> Self {
        let keys = context
            .committee
            .authorities()
            .map(|(_i, a)| a.network_key.clone().into_inner())
            .collect();
        Self { keys }
    }
}

impl sui_tls::Allower for AllowedPublicKeys {
    fn allowed(&self, key: &Ed25519PublicKey) -> bool {
        self.keys.contains(key)
    }
}

fn certificate_server_name(context: &Context) -> String {
    format!("consensus_epoch_{}", context.committee.epoch())
}

#[derive(Debug)]
pub(crate) struct ConnInfo {
    pub(crate) addr: std::net::SocketAddr,
    pub(crate) certificates: Vec<Certificate>,
}

// // Verifies server cert for a given authority.
// struct AuthorityCertVerifier {
//     context: Arc<Context>,
//     authority_index: AuthorityIndex,
// }

// impl AuthorityCertVerifier {
//     fn new(context: Arc<Context>, authority_index: AuthorityIndex) -> Self {
//         Self {
//             context,
//             authority_index,
//         }
//     }
// }

// impl ServerCertVerifier for AuthorityCertVerifier {
//     fn verify_server_cert(
//         &self,
//         end_entity: &Certificate,
//         intermediates: &[Certificate],
//         _server_name: &rustls::ServerName,
//         _scts: &mut dyn Iterator<Item = &[u8]>,
//         _ocsp_response: &[u8],
//         now: std::time::SystemTime,
//     ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
//         let public_key = sui_tls::public_key_from_certificate(end_entity)?;

//         Ok(rustls::client::ServerCertVerified::assertion())
//     }

//     fn request_scts(&self) -> bool {
//         false
//     }
// }

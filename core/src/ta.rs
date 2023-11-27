/*
 * Copyright (C) 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Implementation of a SecretKeeper trusted application (TA).

use crate::store::{KeyValueStore, PolicyGatedStorage};
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use authgraph_core::ag_err;
use authgraph_core::error::Error;
use authgraph_core::key::{
    AesKey, CertChain, EcSignKey, EcVerifyKey, Identity, IdentityVerificationDecision,
    EXPLICIT_KEY_DICE_CERT_CHAIN_VERSION, IDENTITY_VERSION,
};
use authgraph_core::traits::{AesGcm, CryptoTraitImpl, Device, EcDsa, Rng, Sha256};
use authgraph_wire::{ErrorCode, SESSION_ID_LEN};
use coset::{iana, CborSerializable};
use log::{error, warn};
use secretkeeper_comm::data_types::{
    error::Error as SkInternalError,
    error::SecretkeeperError,
    packet::{RequestPacket, ResponsePacket},
    request::Request,
    request_response_impl::{GetVersionRequest, GetVersionResponse, Opcode},
    response::Response,
};

/// Current Secretkeeper version.
const CURRENT_VERSION: u64 = 1;

/// Maximum number of live session keys.
const MAX_SESSIONS: usize = 32;

/// Secretkeeper trusted application instance.
pub struct SecretkeeperTa {
    /// AES-GCM implementation.
    aes_gcm: Box<dyn AesGcm>,

    /// RNG implementation.
    #[allow(dead_code)] // TODO: remove this
    rng: Box<dyn Rng>,

    /// AuthGraph per-boot-key.
    per_boot_key: AesKey,

    /// The signing key corresponding to the leaf of the Secretkeeper identity DICE chain.
    identity_sign_key: Option<EcSignKey>,

    /// Secretkeeper identity.
    identity: Option<Identity>,

    /// Current session keys.
    session_keys: VecDeque<SessionKeyInfo>,

    /// Storage of secrets (& sealing policy)
    _store: PolicyGatedStorage,
}

impl SecretkeeperTa {
    /// Create a TA instance using the provided trait implementations.
    pub fn new(
        ag_impls: &mut CryptoTraitImpl,
        storage_impl: Box<dyn KeyValueStore>,
    ) -> Result<Self, SkInternalError> {
        // Create a per-boot-key for AuthGraph to use.
        let aes_gcm = ag_impls.aes_gcm.box_clone();
        let rng = ag_impls.rng.box_clone();
        let per_boot_key = aes_gcm.generate_key(&mut *ag_impls.rng).map_err(|e| {
            error!("Failed to generate per-boot key: {e:?}");
            SkInternalError::UnexpectedError
        })?;

        // TODO: replace with actual Secretkeeper identity and signing key.
        let (priv_key, pub_key) =
            authgraph_boringssl::ec::create_p256_key_pair(iana::Algorithm::ES256).map_err(|e| {
                error!("Failed to generate P-256 keypair: {e:?}");
                SkInternalError::UnexpectedError
            })?;
        let identity_sign_key = EcSignKey::P256(priv_key);
        let identity = Identity {
            version: IDENTITY_VERSION,
            cert_chain: CertChain {
                version: EXPLICIT_KEY_DICE_CERT_CHAIN_VERSION,
                root_key: EcVerifyKey::P256(pub_key),
                dice_cert_chain: None,
            },
            policy: None,
        };
        let store = PolicyGatedStorage::init(storage_impl);

        Ok(Self {
            aes_gcm,
            rng,
            per_boot_key,
            identity_sign_key: Some(identity_sign_key),
            identity: Some(identity),
            session_keys: VecDeque::new(),
            _store: store,
        })
    }

    /// Process a single serialized request, returning a serialized response.
    pub fn process(&mut self, req: &[u8]) -> Vec<u8> {
        // TODO(b/291224769) The request will need to be decrypted & response need to be encrypted
        // with key & related artifacts pre-shared via Authgraph Key Exchange HAL.
        self.process_inner(req).unwrap_or_else(
            // SecretkeeperError is also a valid 'Response', serialize to a response packet.
            |sk_err| {
                Response::serialize_to_packet(&sk_err)
                    .to_vec()
                    .expect("Panicking due to serialization failing")
            },
        )
    }
    fn process_inner(&self, req: &[u8]) -> Result<Vec<u8>, SecretkeeperError> {
        let req_packet = RequestPacket::from_slice(req).map_err(|e| {
            error!("Failed to get Request packet from bytes: {e:?}");
            SecretkeeperError::RequestMalformed
        })?;
        let rsp_packet =
            match req_packet.opcode().map_err(|_| SecretkeeperError::RequestMalformed)? {
                Opcode::GetVersion => Self::get_version(req_packet)?,
                _ => todo!("TODO(b/291224769): Unimplemented operations"),
            };

        rsp_packet.to_vec().map_err(|_| SecretkeeperError::UnexpectedServerError)
    }

    fn get_version(req: RequestPacket) -> Result<ResponsePacket, SecretkeeperError> {
        // Deserialization really just verifies the structural integrity of the request such
        // as args being empty.
        let _req = GetVersionRequest::deserialize_from_packet(req)
            .map_err(|_| SecretkeeperError::RequestMalformed)?;
        let rsp = GetVersionResponse { version: CURRENT_VERSION };
        Ok(rsp.serialize_to_packet())
    }

    #[allow(dead_code)] // TODO: remove this
    fn keys_for_session(&self, session_id: &[u8; SESSION_ID_LEN]) -> Option<&SessionKeyInfo> {
        self.session_keys.iter().find(|info| info.session_id == *session_id)
    }
}

impl Device for SecretkeeperTa {
    fn get_or_create_per_boot_key(&self, _: &dyn AesGcm, _: &mut dyn Rng) -> Result<AesKey, Error> {
        self.get_per_boot_key()
    }
    fn get_per_boot_key(&self) -> Result<AesKey, Error> {
        Ok(self.per_boot_key.clone())
    }
    fn get_identity(&self) -> Result<(Option<EcSignKey>, Identity), Error> {
        Ok((
            self.identity_sign_key.clone(),
            self.identity
                .clone()
                .ok_or_else(|| ag_err!(InternalError, "Secretkeeper identity not available!"))?,
        ))
    }
    fn get_cose_sign_algorithm(&self) -> iana::Algorithm {
        match &self.identity_sign_key {
            Some(EcSignKey::Ed25519(_)) => iana::Algorithm::EdDSA,
            Some(EcSignKey::P256(_)) => iana::Algorithm::ES256,
            Some(EcSignKey::P384(_)) => iana::Algorithm::ES384,
            _ => {
                error!("Unknown COSE_Sign algorithm");
                iana::Algorithm::ES256
            }
        }
    }

    fn sign_data(&self, _ecdsa: &dyn EcDsa, _data: &[u8]) -> Result<Vec<u8>, Error> {
        // `get_identity()` returns a key, so signing should be handled elsewhere.
        Err(ag_err!(Unimplemented, "unexpected signing request"))
    }

    fn evaluate_identity(
        &self,
        _curr: &Identity,
        _prev: &Identity,
    ) -> Result<IdentityVerificationDecision, Error> {
        Err(ag_err!(Unimplemented, "not yet required"))
    }

    fn record_shared_sessions(
        &mut self,
        peer_identity: &Identity,
        session_id: &[u8; 32],
        shared_keys: &[Vec<u8>; 2],
        _sha256: &dyn Sha256,
    ) -> Result<(), Error> {
        if self.session_keys.len() >= MAX_SESSIONS {
            warn!("Dropping oldest session key");
            self.session_keys.pop_front();
        }
        let send_key =
            authgraph_core::arc::decipher_arc(&self.per_boot_key, &shared_keys[0], &*self.aes_gcm)?;
        let recv_key =
            authgraph_core::arc::decipher_arc(&self.per_boot_key, &shared_keys[1], &*self.aes_gcm)?;

        // We assume that the session ID is unique and not already present in `session_keys`.
        self.session_keys.push_back(SessionKeyInfo {
            _peer_identity: peer_identity.clone(),
            session_id: *session_id,
            send_key: send_key.payload.try_into()?,
            recv_key: recv_key.payload.try_into()?,
        });
        Ok(())
    }

    fn validate_shared_sessions(
        &self,
        _peer_identity: &Identity,
        _session_id: &[u8; 32],
        _shared_keys: &[Vec<u8>],
        _sha256: &dyn Sha256,
    ) -> Result<(), Error> {
        // TODO: implement
        Ok(())
    }
}

#[allow(dead_code)] // TODO: remove this
struct SessionKeyInfo {
    _peer_identity: Identity,
    session_id: [u8; 32],
    send_key: AesKey,
    recv_key: AesKey,
}

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

use crate::cipher;
use crate::store::{KeyValueStore, PolicyGatedStorage};
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::ToString;
use alloc::vec::Vec;
use authgraph_core::ag_err;
use authgraph_core::error::Error;
use authgraph_core::key::{
    AesKey, CertChain, EcSignKey, EcVerifyKey, Identity, IdentityVerificationDecision,
    EXPLICIT_KEY_DICE_CERT_CHAIN_VERSION, IDENTITY_VERSION,
};
use authgraph_core::traits::{AesGcm, CryptoTraitImpl, Device, EcDsa, Rng, Sha256};
use authgraph_wire::{ErrorCode, SESSION_ID_LEN};
use coset::{iana, CborSerializable, CoseEncrypt0};
use log::{error, trace, warn};
use secretkeeper_comm::data_types::{
    error::Error as SkInternalError,
    error::SecretkeeperError,
    packet::{RequestPacket, ResponsePacket},
    request::Request,
    request_response_impl::{
        GetSecretRequest, GetSecretResponse, GetVersionRequest, GetVersionResponse, Opcode,
        StoreSecretRequest, StoreSecretResponse,
    },
    response::Response,
};
use secretkeeper_comm::wire::{
    AidlErrorCode, ApiError, PerformOpReq, PerformOpResponse, PerformOpSuccessRsp, SecretId,
};

/// Current Secretkeeper version.
const CURRENT_VERSION: u64 = 1;

/// Maximum number of live session keys.
const MAX_SESSIONS: usize = 32;

// TODO: Remove the hypothetical dice chain, we will need dice chain, alongwith secrets for
// signing it for testing.
// Developer note: I've got this chain by patching libdice_policy such that it dumps the
// dice_policy corresponding to a hypothetical dice_chain (which is hard-coded input in
// VTS secretkeeper_test_client.rs)
const HYPOTHETICAL_DICE_CHAIN: [u8; 66] = [
    0x82, 0xA1, 0x01, 0x00, 0x84, 0x40, 0xA0, 0x58, 0x34, 0xA3, 0x01, 0x73, 0x74, 0x65, 0x73, 0x74,
    0x69, 0x6E, 0x67, 0x5F, 0x64, 0x69, 0x63, 0x65, 0x5F, 0x70, 0x6F, 0x6C, 0x69, 0x63, 0x79, 0x02,
    0x74, 0x75, 0x6E, 0x63, 0x6F, 0x6E, 0x73, 0x74, 0x72, 0x61, 0x69, 0x6E, 0x65, 0x64, 0x5F, 0x73,
    0x74, 0x72, 0x69, 0x6E, 0x67, 0x03, 0x46, 0xA1, 0x18, 0x64, 0x19, 0xE9, 0x75, 0x44, 0x64, 0x64,
    0x65, 0x66,
];

/// Macro to build an [`ApiError`] instance.
/// E.g. use: `aidl_err!(InternalError, "some {} format", arg)`.
#[macro_export]
macro_rules! aidl_err {
    { $error_code:ident, $($arg:tt)+ } => {
        ApiError {
            err_code: AidlErrorCode::$error_code,
            msg: alloc::format!("{}:{}: {}", file!(), line!(), format_args!($($arg)+))
        }
    };
}

/// Secretkeeper trusted application instance.
pub struct SecretkeeperTa {
    /// AES-GCM implementation.
    aes_gcm: Box<dyn AesGcm>,

    /// RNG implementation.
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
    store: PolicyGatedStorage,
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
            store,
        })
    }

    /// Process a single serialized request, returning a serialized response (even on failure).
    pub fn process(&mut self, req_data: &[u8]) -> Vec<u8> {
        let (req_code, rsp) = match PerformOpReq::from_slice(req_data) {
            Ok(req) => {
                trace!("-> TA: received request {:?}", req.code());
                (Some(req.code()), self.process_req(req))
            }
            Err(e) => {
                error!("failed to decode CBOR request: {:?}", e);
                (None, PerformOpResponse::Failure(aidl_err!(InternalError, "CBOR decode failure")))
            }
        };
        trace!("<- TA: send response for {:?} rc {:?}", req_code, rsp.err_code());
        rsp.to_vec().unwrap_or_else(|e| {
            error!("failed to encode CBOR response: {:?}", e);
            invalid_cbor_rsp_data().to_vec()
        })
    }

    /// Process a single request, returning a [`PerformOpResponse`].
    fn process_req(&mut self, req: PerformOpReq) -> PerformOpResponse {
        let code = req.code();
        let result = match req {
            PerformOpReq::SecretManagement(encrypt0) => {
                self.secret_management(&encrypt0).map(PerformOpSuccessRsp::ProtectedResponse)
            }
            PerformOpReq::DeleteIds(ids) => {
                self.delete_ids(ids).map(|_| PerformOpSuccessRsp::Empty)
            }
            PerformOpReq::DeleteAll => self.delete_all().map(|_| PerformOpSuccessRsp::Empty),
        };
        match result {
            Ok(rsp) => PerformOpResponse::Success(rsp),
            Err(err) => {
                warn!("failing {:?} request: {:?}", code, err);
                PerformOpResponse::Failure(err)
            }
        }
    }

    fn delete_ids(&mut self, ids: Vec<SecretId>) -> Result<(), ApiError> {
        Err(ApiError {
            err_code: AidlErrorCode::InternalError,
            msg: alloc::format!("TODO with {ids:?}"),
        })
    }

    fn delete_all(&mut self) -> Result<(), ApiError> {
        Err(ApiError { err_code: AidlErrorCode::InternalError, msg: "TODO".to_string() })
    }

    fn secret_management(&mut self, encrypt0: &[u8]) -> Result<Vec<u8>, ApiError> {
        let (req, session_keys) = self.decrypt_request(encrypt0)?;
        let result = self.process_inner(&req);

        // An inner failure still converts to a response message that gets encrypted.
        let rsp_data = match result {
            Ok(data) => data,
            Err(e) => e
                .serialize_to_packet()
                .to_vec()
                .map_err(|_e| aidl_err!(InternalError, "failed to encode err rsp"))?,
        };
        self.encrypt_response(&session_keys, &rsp_data)
    }

    fn process_inner(&mut self, req: &[u8]) -> Result<Vec<u8>, SecretkeeperError> {
        let req_packet = RequestPacket::from_slice(req).map_err(|e| {
            error!("Failed to get Request packet from bytes: {e:?}");
            SecretkeeperError::RequestMalformed
        })?;
        let rsp_packet =
            match req_packet.opcode().map_err(|_| SecretkeeperError::RequestMalformed)? {
                Opcode::GetVersion => Self::get_version(req_packet)?,
                Opcode::StoreSecret => self.store_secret(req_packet)?,
                Opcode::GetSecret => self.get_secret(req_packet)?,
                _ => panic!("Unknown operation.."),
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

    fn store_secret(
        &mut self,
        request: RequestPacket,
    ) -> Result<ResponsePacket, SecretkeeperError> {
        let request = StoreSecretRequest::deserialize_from_packet(request)
            .map_err(|_| SecretkeeperError::RequestMalformed)?;
        self.store.store(
            request.id,
            request.secret,
            request.sealing_policy,
            // TODO(b/291228560): Identify the session & use the corresponding `Identity`
            // instead of hardcoded chain.
            &HYPOTHETICAL_DICE_CHAIN,
        )?;
        let response = StoreSecretResponse {};
        Ok(response.serialize_to_packet())
    }

    fn get_secret(&mut self, request: RequestPacket) -> Result<ResponsePacket, SecretkeeperError> {
        let request = GetSecretRequest::deserialize_from_packet(request)
            .map_err(|_| SecretkeeperError::RequestMalformed)?;
        let secret = self.store.get(
            &request.id,
            // TODO(b/291228560): Dice chain should be received during AuthgraphKeyExchange
            // instead of being hard-coded.
            &HYPOTHETICAL_DICE_CHAIN,
            request.updated_sealing_policy,
        )?;
        let response = GetSecretResponse { secret };
        Ok(response.serialize_to_packet())
    }

    // "SSL added and removed here :-)"
    fn keys_for_session(&self, session_id: &[u8; SESSION_ID_LEN]) -> Option<&SessionKeyInfo> {
        self.session_keys.iter().find(|info| info.session_id == *session_id)
    }
    fn decrypt_request(&self, req: &[u8]) -> Result<(Vec<u8>, SessionKeyInfo), ApiError> {
        let encrypt0 = CoseEncrypt0::from_slice(req)
            .map_err(|_e| aidl_err!(RequestMalformed, "malformed COSE_Encrypt0"))?;
        let session_keys = self
            .keys_for_session(&encrypt0.protected.header.key_id[..].try_into().map_err(|e| {
                aidl_err!(RequestMalformed, "session key of unexpected size: {e:?}")
            })?)
            .ok_or_else(|| aidl_err!(UnknownKeyId, "session key not found"))?;
        let payload = cipher::decrypt_message(&*self.aes_gcm, &session_keys.recv_key, &encrypt0)?;
        Ok((payload, session_keys.clone()))
    }
    fn encrypt_response(
        &self,
        session_keys: &SessionKeyInfo,
        rsp: &[u8],
    ) -> Result<Vec<u8>, ApiError> {
        cipher::encrypt_message(
            &*self.aes_gcm,
            &*self.rng,
            &session_keys.send_key,
            &session_keys.session_id,
            rsp,
        )
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

#[derive(Clone)]
struct SessionKeyInfo {
    _peer_identity: Identity,
    session_id: [u8; 32],
    send_key: AesKey,
    recv_key: AesKey,
}

/// Hand-encoded [`PerformOpResponse`] data for [`AidlErrorCode::InternalError`].
/// Does not perform CBOR serialization (and so is suitable for error reporting if/when
/// CBOR serialization fails).
// TODO: add a unit test that confirms that this hand-encoded data is correct
fn invalid_cbor_rsp_data() -> [u8; 3] {
    [
        0x82, // 2-arr
        0x02, // int, value 2
        0x60, // 0-tstr
    ]
}

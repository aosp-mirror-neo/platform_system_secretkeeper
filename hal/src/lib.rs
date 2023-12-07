// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

//! Crate that holds common code for a Secretkeeper HAL service.

use android_hardware_security_secretkeeper::aidl::android::hardware::security::secretkeeper::ISecretkeeper::{
    ISecretkeeper, BnSecretkeeper
};
use android_hardware_security_authgraph::aidl::android::hardware::security::authgraph::{
    IAuthGraphKeyExchange::IAuthGraphKeyExchange,
};
use authgraph_hal::channel::SerializedChannel;
use authgraph_hal::service::AuthGraphService;

/// Implementation of the Secretkeeper HAL service, communicating with a TA
/// in a secure environment via a communication channel.
pub struct SecretkeeperService<T: SerializedChannel + 'static> {
    authgraph: binder::Strong<dyn IAuthGraphKeyExchange>,
    channel: T,
}

impl<T: SerializedChannel + 'static> SecretkeeperService<T> {
    /// Construct a new instance that uses the provided channels.
    pub fn new<S: SerializedChannel + 'static>(sk_channel: T, ag_channel: S) -> Self {
        Self { authgraph: AuthGraphService::new_as_binder(ag_channel), channel: sk_channel }
    }

    /// Create a new instance wrapped in a proxy object.
    pub fn new_as_binder<S: SerializedChannel + 'static>(
        sk_channel: T,
        ag_channel: S,
    ) -> binder::Strong<dyn ISecretkeeper> {
        BnSecretkeeper::new_binder(
            Self::new(sk_channel, ag_channel),
            binder::BinderFeatures::default(),
        )
    }
}

impl<T: SerializedChannel> binder::Interface for SecretkeeperService<T> {}

/// Implement the `ISecretkeeper` interface.
impl<T: SerializedChannel> ISecretkeeper for SecretkeeperService<T> {
    fn processSecretManagementRequest(&self, req: &[u8]) -> binder::Result<Vec<u8>> {
        // Pass the request to the channel, and read the response.
        self.channel.execute(req)
    }
    fn getAuthGraphKe(&self) -> binder::Result<binder::Strong<dyn IAuthGraphKeyExchange>> {
        Ok(self.authgraph.clone())
    }
}

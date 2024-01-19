# Secretkeeper

Secretkeeper provides secure storage of secrets on behalf of other components in Android.
It is specified as [a HAL][secretkeeperhal] and must be implemented in an environment with
privilege higher than any of its clients. Typically this will be a trusted execution environment
such as ARM TrustZone.

The core SecretManagement API is a [CBOR based protocol][secretmanagement_cddl] and can be  used
to store (& get) 32 bytes of secret data. Secretkeeper supports establishing secure channel with
clients as well as deletion of some or all data.

### AuthGraph key exchange

The requests (from client) & responses (from Secretkeeper) must be encrypted using symmetric keys
agreed between the client & service. For this, Secretkeeper (& client) must implement the
[AuthGraph key exchange protocol][authgraphke] to establish a secure channel between them.

In the key exchange protocol, the client acts as P1 (source) and Secretkeeper as P2 (sink). The
interface returned by [getAuthGraphKe()][getauthgraphke] can be used to invoke methods on the sink.

### Policy Gated Storage

The storage layer of Secretkeeper, in addition to conventional storage, provides DICE
policy based access control. A client can restrict the access to its stored entry.

#### Storage

The underlying storage of Secretkeeper should offer the following security guarantees:

1. Confidentiality: No entity (of security privilege lower than Secretkeeper) should be able to get
   a client's data in clear.
2. Integrity: The data is protected against malicious Android OS tampering with database. i.e., if
   Android (userspace & kernel) tampers with the client's secret, the Secretkeeper service must be
   able to detect it & return error when clients requests for their secrets.
   **The integrity requirements also include rollback protection i.e., reverting the database
   into an old state should be detected.**
3. Persistence: The data is persistent across device boot.
   Note: Denial of service is not in scope. A malicious Android may be able to delete data.
   In ideal situation, the data should be persistent.

#### Access control

Secretkeeper uses [DICE policy][DicePolicyCDDL] based access control. Each secret is associated
with a sealing policy, which is a DICE policy. This is a required input while storing a secret.
Further access to this secret is restricted to clients whose DICE chain adheres to the
corresponding sealing policy.

## Reference code

Android provides the reference implementation of Secretkeeper as well as the required AuthGraph Key
exchange HAL. The implementation is modular and easily configurable. For example,
partners can plug in their implementation of AES-GCM, RNG instead of using the BoringSSL
implementations.

Navigating this project:
1. [./core/][sk_core_dir]: Contains the reference implementation of Secretkeeper TA.
2. [./hal/][sk_hal_dir]: Contains the reference implementation of Secretkeeper HAL.
3. [./client/][sk_client_dir]: A client library for Secretkeeper, which can be used for managing
   sessions with Secretkeeper, sending requests etc.
4. [./comm/][sk_comm_dir]: Secretkeeper is a CBOR heavy protocol, the Rust definition
   of Requests/Response/Arguments/Errors is contained in this directory.
   Additionally, Rust types for supporting the CBOR based communication between the TA and HAL is
   also exported here. This is used by secretkeeper_core, secretkeeper_hal and secretkeeper_client.
5. [./dice_policy/][dice_policy_dir]: Contains code for building dice_policies as well
   as well as matching them against Dice chain. As explained [here](#-Policy-Gated-Storage), this
   forms the foundation of Policy Gated Storage in Secretkeeper.

Outside this directory:
1. Secretkeeper HAL Spec: [hardware/interfaces/security/secretkeeper/aidl/android/hardware/security/secretkeeper/ISecretkeeper.aidl][secretkeeperhal]
2. [Vendor Test Suite for Secretkeeper][secretkeeper_vts]
3. [HAL Integration for Trusty][sk_hal_trusty]
4. [TA Integration for Trusty][sk_ta_trusty]
5. [Command line test tool for interacting with Secretkeeper][secretkeeper_cli]
6. [AuthGraph HAL Spec & Test Suite][authgraphhal_dir]
7. AuthGraph Reference implementation: [system/authgraph/][authgraph_ref]

[sk_core_dir]: https://cs.android.com/android/platform/superproject/main/+/main:system/secretkeeper/core/
[sk_hal_dir]: https://cs.android.com/android/platform/superproject/main/+/main:system/secretkeeper/hal/
[sk_client_dir]: https://cs.android.com/android/platform/superproject/main/+/main:system/secretkeeper/client/
[sk_comm_dir]: https://cs.android.com/android/platform/superproject/main/+/main:system/secretkeeper/comm/
[dice_policy_dir]: https://cs.android.com/android/platform/superproject/main/+/main:system/secretkeeper/dice_policy/
[secretkeeper_vts]: https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/secretkeeper/aidl/vts/secretkeeper_test_client.rs
[sk_hal_trusty]: https://cs.android.com/android/platform/superproject/main/+/main:system/core/trusty/secretkeeper/src/hal_main.rs
[sk_ta_trusty]: https://android.googlesource.com/trusty/app/secretkeeper/+/refs/heads/master/lib.rs
[secretkeeper_cli]: https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/secretkeeper/aidl/vts/secretkeeper_cli.rs
[authgraphhal_dir]: https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/authgraph/aidl/
[authgraph_ref]: https://cs.android.com/android/platform/superproject/main/+/main:system/authgraph/

## Example usage: Rollback protected secrets of Microdroid based pVMs.

Microdroid instances use Secretkeeper to store their secrets while protecting against the Rollback
attacks on the boot images & packages. Such secrets (and data protected by the secrets) are
accessible on updates but not on downgrades of boot images and apks.

[authgraphke]: https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/authgraph/aidl/android/hardware/security/authgraph/IAuthGraphKeyExchange.aidl
[getauthgraphke]: https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/secretkeeper/aidl/android/hardware/security/secretkeeper/ISecretkeeper.aidl?q=getAuthGraphKe
[secretkeeperhal]: https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/secretkeeper/aidl/android/hardware/security/secretkeeper/ISecretkeeper.aidl
[secretmanagement_cddl]: https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/secretkeeper/aidl/android/hardware/security/secretkeeper/SecretManagement.cddl
[DicePolicyCDDL]: https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/authgraph/aidl/android/hardware/security/authgraph/DicePolicy.cddl

### Secretkeeper public key

As described [above](#authgraph-key-exchange), Microdroid as a Secretkeeper
client establishes a secure channel with the Secretkeeper implementation using
the AuthGraph key exchange protocol. As part of this Microdroid needs to verify
that it is communicating with the real Secretkeeper.

To achieve this the Secretkeeper implementation should generate a per-boot key
pair and use that as its identity in the AuthGraph protocol. The public key from
the pair then needs to be securely communicated to the Microdroid VM which uses
it to verify the identity of Secretkeeper.

The public key is transported as a CBOR-encoded COSE_key, as a PubKeyEd25519 /
PubKeyECDSA256 / PubKeyECDSA384 as defined in
[generateCertificateRequestV2.cddl][pubkeycddl].

Microdroid expects the public key to be present in the Linux device tree as the
value of the `secretkeeper-key` property of the `/avf` node - exposed to
userspace at `/sys/firmware/devicetree/base/avf/secretkeeper-key`.

When a protected VM is started, AVF populates this property in the VM DT `/avf`
node from the corresponding property in the `/avf/reference/avf` node in the
host DT. pvmfw verifies that the value is correct using the VM reference DT that
is included in the pvmfw [configuration data][pvmfwconfig].

The [Android bootloader][androidbootloader] should request the public key from
the Secretkeeper implementation at boot time and populate it in both the host
Android DT and the VM Reference DT for pvmfw.

The reference code for Secretkeeper defines a protocol that can be used by the
bootloader to retrieve the public key; see
[core/src/ta/bootloader.rs][skbootloader].

[pubkeycddl]: https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/rkp/aidl/android/hardware/security/keymint/generateCertificateRequestV2.cddl;l=143
[pvmfwconfig]: https://android.googlesource.com/platform/packages/modules/Virtualization/+/refs/heads/main/pvmfw/README.md#configuration-data-format
[androidbootloader]: https://source.android.com/docs/core/architecture/bootloader
[skbootloader]: https://cs.android.com/android/platform/superproject/main/+/main:system/secretkeeper/core/src/ta/bootloader.rs

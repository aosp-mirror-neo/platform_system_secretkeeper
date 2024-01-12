# Secretkeeper

Secretkeeper provides secure storage of secrets on behalf of other components in Android.
It is specified as [a HAL][secretkeeperhal] and must be implemented in an environment with
privilege higher than any of its clients. Typically this will be a trusted execution environment
such as ARM TrustZone.

The core SecretManagement API is a [CBOR based protocol][secretmanagement_cddl] and can be  used
to store (& get) 32 bytes of secret data. Secretkeeper supports establishing secure channel with
clients as well as deletion of some or all data.

## AuthGraph key exchange

The requests (from client) & responses (from Secretkeeper) must be encrypted using symmetric keys
agreed between the client & service. For this, Secretkeeper (& client) must implement the
[AuthGraph key exchange protocol][authgraphke] to establish a secure channel between them.

In the key exchange protocol, the client acts as P1 (source) and Secretkeeper as P2 (sink). The
interface returned by [getAuthGraphKe()][getauthgraphke] can be used to invoke methods on the sink.

## Policy Gated Storage

The storage layer of Secretkeeper, in addition to conventional storage, provides DICE
policy based access control. A client can restrict the access to its stored entry.

### Storage

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

## Policy based Access control

Secretkeeper uses [DICE policy][DicePolicyCDDL] based access control. Each secret is associated
with a sealing policy, which is a DICE policy. This is a required input while storing a secret.
Further access to this secret is restricted to clients whose DICE chain adheres to the
corresponding sealing policy.

# Example usage: Rollback protected secrets of Microdroid based pVMs.

Microdroid instances use Secretkeeper to store their secrets while protecting against the Rollback
attacks on the boot images & packages. Such secrets (and data protected by the secrets) are
accessible on updates but not on downgrades of boot images and apks.

[authgraphke]: https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/authgraph/aidl/android/hardware/security/authgraph/IAuthGraphKeyExchange.aidl
[getauthgraphke]: https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/secretkeeper/aidl/android/hardware/security/secretkeeper/ISecretkeeper.aidl;l=51
[secretkeeperhal]: https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/secretkeeper/aidl/android/hardware/security/secretkeeper/ISecretkeeper.aidl
[secretmanagement_cddl]: https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/secretkeeper/aidl/android/hardware/security/secretkeeper/SecretManagement.cddl
[DicePolicyCDDL]: https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/authgraph/aidl/android/hardware/security/authgraph/DicePolicy.cddl

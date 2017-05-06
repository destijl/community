# Encryption

## Abstract

The scope of this proposal is to ensure that resources can be encrypted at the
datastore layer. Encryption will be optional for any resource but will be used
by default for the Secret resource. Secrets are already protected in transit via
TLS.

Full disk encryption of the volumes storing etcd data is already expected as
standard security hygiene.  Adding the proposed encryption inside the database
defends against malicious parties gaining access to:

- The etcd API
- etcd backups; or
- A running etcd instance without access to memory of the etcd process.

Allowing sensitive data to be encrypted adheres to best practices as well as
other requirements such as HIPAA.

## High level design

Before a resource is written to etcd and before it is read, an encryption
provider will take the plaintext data and encrypt/decrypt it.  These providers
will be able to be created and turned on depending on the users needs or
requirements and will adhere to an encryption interface.  This interface will
provide the abstraction to allow various encryption mechanisms to be
implemented, as well as for the method of encryption to be rotated over time.

For the first iteration, a default provider that handles encryption in-process
using a locally stored key on disk will be developed.

## Kubernetes Storage Changes

Kubernetes requires that an update that does not change the serialized form of
object not be persisted to etcd to prevent other components from seeing no-op
updates.

This must be done within the Kubernetes storage interfaces - we will introduce a
new API to the Kube storage layer that transforms the serialized object into the
desired at-rest form and provides hints as to whether no-op updates should still
persist (when key rotation is in effect).

```go
// ValueTransformer allows a string value to be transformed before being read from or written to the underlying store. The methods
// must be able to undo the transformation caused by the other.
type ValueTransformer interface {
        // TransformFromStorage may transform the provided data from its underlying
        // storage representation or return an error.  Stale is true if the object
        // on disk is stale (encrypted with an older key) and a write to etcd
        // should be issued, even if the contents of the object have not changed.
        TransformFromStorage([]byte) (data []byte, stale bool, err error)
        // TransformToStorage may transform the provided data into the appropriate form in storage or return an error.
        TransformToStorage([]byte) (data []byte, err error)
}
```

When the storage layer of Kubernetes is initialized for some resource, an
implementation of this interface that manages encryption will be passed down.
Other resources can use a no-op provider by default.

## Encryption Provider

An encryption provider implements the ValueTransformer interface. Out of the box
this proposal will implement encryption using a standard AES-GCM performing
AEAD, using the standard Go library for AES-GCM.

Each encryption provider will have a unique string identifier to ensure
versioning of contents on disk and to allow future schemes to be replaced.

During encryption, only a single provider is required.  During decryption,
multiple providers or keys may be in use (when migrating from an older version
of a provider, or when rotating keys), and thus the ValueTransformer
implementation must be able to delegate to the appropriate provider.

### AES-GCM Encryption provider for 1.7 alpha

Implemented in https://github.com/kubernetes/kubernetes/pull/41939.

TODO: Decide if https://godoc.org/golang.org/x/crypto/nacl/secretbox should be
used instead.

The simplest possible provider is an AES-GCM encrypter/decrypter using AEAD,
where we create a unique nonce on each new write to etcd, use that as the IV for
AES-GCM of the value (the JSON or protobuf data) along with a set of
authenticated data to create the ciphertext, and then on decryption use the
nonce and the authenticated data to decode.  The keys come from configuration on
the local disk (potentially decrypted at startup time using a stronger password
protected key, or in the future from an alternative source).

The provider will be assigned a versioned identifier to uniquely pair the
implementation with the data at rest, such as “k8s-aes-gcm-v1”.  Any
implementation that attempts to decode data associated with this provider id
must follow a known structure and apply a specific algorithm.

The provider would take a set of keys and unique key identifiers from the
command line, with the key values stored on disk.  One key is identified as the
write key, all others are used to decrypt data from previous keys.  Keys must be
rotated more often than every 2^32 writes.

The provider should use the recommended Go defaults for all crypto settings
unless otherwise noted.  We should use AES-256 keys (32 bytes).

Process for transforming a value (object encoded as JSON or protobuf) to and
from stable storage will look like the following:

Layout as written to etcd2 (json safe string only):
```
NONCE := read(/dev/urandom)
PLAIN_TEXT := <VALUE>
AUTHENTICATED_DATA := ETCD_KEY
CIPHER_TEXT := aes_gcm_encrypt(KEY, IV:NONCE, PLAIN_TEXT, A:AUTHENTICATED_DATA)
BASE64_DATA := base64(<NONCE><CIPHER_TEXT>)
STORED_DATA := <PROVIDER>:<KEY_ID>:<BASE64_DATA>
```

Layout as written to etcd3 (bytes):
```
NONCE := read(/dev/urandom)
PLAIN_TEXT := <VALUE>
AUTHENTICATED_DATA := ETCD_KEY
CIPHER_TEXT := aes_gcm_encrypt(KEY, IV:NONCE, PLAIN_TEXT, A:AUTHENTICATED_DATA)
STORED_DATA := <PROVIDER_ID>:<KEY_ID>:<NONCE><AUTHENTICATED_DATA><CIPHER_TEXT>
```

Pseudo-code for encrypt (golang):
```go
block := aes.NewCipher(primaryKeyString)
aead := cipher.NewGCM(c.block)
keyId := primaryKeyId

// for each write
nonce := make([]byte, block.BlockSize())
io.ReadFull(crypto_rand.Reader, nonce)
authenticatedData := ETCD_KEY
cipherText := aead.Seal(nil, nonce, value, authenticatedData)
storedData := providerId + keyId + base64.Encode(nonce + authenticatedData + cipherText)
```

Pseudo-code for decrypt (golang):
```go
// for each read
providerId, keyId, base64Encoded := // slice provider and key from value

// ensure this provider is the one handling providerId
aead := // lookup an aead instance for keyId or error
bytes := base64.Decode(base64Encoded)
nonce, authenticatedData, cipherText := // slice from bytes
out, err := aead.Open(nil, nonce, cipherText, authenticatedData)
```

## Key Generation

For the 1.7 alpha there will be no key generation, the encryption provider
simply expects a key to be passed in. Future versions could generate a random
key, and display it one-time to the user, who would then be responsible for
proper storage and safekeeping.

## Key Distribution and Rotation

For the 1.7 alpha we want to support a simple distribution and rotation scheme.

To enable key rotation a common pattern is to have keys used for resource
encryption encrypted by another set of keys (Key Encryption Keys aka KEK).  The
keys used for encrypting kubernetes resources (Data Encryption Keys, aka DEK)
are generated by the apiserver and stored encrypted with one of the KEKs.

In future versions, storing a KEK off-host and retrieving it when required from
AWS KMS, Google Cloud KMS, Hashicorp Vault etc. should be possible. Using a
remote encrypt/decrypt API offered by an external store will not be supported
for performance reasons.

### Option 1: Simple List of DEKs on disk

To enable encryption a user calls PUT on a /rotate API endpoint. This causes a
new Data Encryption Key (DEK) to be created and written to a file on the API
master. The master is then restarted to pick up the new file.  Subsequent calls
to rotate will prepend new keys to the file such that the first key is always
current.

Questions:

 - does this work if you have multiple masters?
 - how can a user back up the encryption keys?

### Option 2: Encrypted DEKs in etcd, KEKs on disk

In order to take an API driven approach for key rotation, new API objects will
be defined:

* Key Encryption Key (KEK) - key used to unlock the Data Encryption Key. Stored
  on API server nodes.
* Data Encryption Key (DEK) - long-lived secret encrypted with a KEK. Stored in
  etcd encrypted. Unencrypted in-memory in API servers.
* KEK Slot - to support KEK rotation there will be an ordered list of KEKs
  stored in the KEK DB. The current active KEK slot number, is stored in etcd
  for consistency.
* KEK DB - a file with N KEKs in a JSON list. KEK[0], by definition, is null.

```go
type DataEncryptionKey struct {
    ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
    Value string    // Encrypted
}
```

```go
type KeyEncryptionKeySlot struct {
    ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
    Slot int
}
```

```go
type KeyEncryptionKeyDatabase struct {
    metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
    Keys []string
}
```

To enable encryption a user will issue a PUT to an endpoint such as `/rotate`.
If this is the first time this API has ever been called the API server will
generate a key (unecrypted DEK), encrypt it with the KEK in slot 1, and encrypt
all secrets with the DEK. If this is the second + N time the API has been called
the API server will encrypt the DEK with the KEK in slot N+1 and do a
compare-and-swap on the DEK stored in etcd. There will be one DEK per database.

If this API is called and a KEK doesn't exist in the KEK DB at slot N+1 a 400 is
returned. `kubectl` will have support for calling the rotate API endpoint
eventually. To account for failure scenarios during key rotation, the old and
new DEK will be stored in etcd during the rotation.

## Master Configuration

In order to enable encryption, a user must first create a KEK DB file and tell
the API server to use it with --key-encryption-key-db-path=/path/to/kekdb/file.
The file will be a simple YAML file that lists all of the keys:

```yaml
kind: KeyEncryptionKeyDatabase
version: v1
keys:
 - foo
 - bar
 - baz
```

The user will also need to specify the encryption provider and the resources to encrypt as follows:
```yaml
--key-encryption-key-db-path=/path/to/key-encryption-key/db
--encryption-provider=default
--encrypt-resource=v1/Secrets
--encrypt-resource=v1/ConfigMap
```

As mentioned previously, the first pass at encryption will only support the default encryption provider.

## Additional Considerations

### Other encryption providers

It should be easy to introduce new variations on the basic provider - such as
those that require a password via STDIN on startup to decrypt the keys on disk,
or wish to exchange a temporary token on disk for the actual keys from a third
party security server.

We expect that the provider implementation may therefore be layered or composed
and that as much as possible providers should be separated behind interfaces.

### Potential providers

* A local HSM implementation that retrieves the keys from the secure enclave
  prior to reusing the AES-GCM implementation (initialization of keys only)
* Exchanging a local temporary token for the actual decryption tokens from a
  networked secret vault
* Decrypting the AES-256 keys from disk using asymmetric encryption combined
  with a user input password
* Sending the data over the network to a key management system for encryption
  and decryption (Google KMS, Amazon KMS, Hashicorp Vault w/ Transit backend)

### Backwards Compatibility

Once a user encrypts any resource in etcd, they are locked to that Kubernetes
version and higher unless they choose to manually decrypt that resource in etcd.
This will be discouraged. It will be highly recommended that users discern if
their Kubernetes cluster is on a stable version before enabling encryption.

### Performance

Introducing even a relatively well tuned AES-GCM implementation is likely to
have performance implications for Kubernetes.  Fortunately, existing
optimizations occur above the storage layer and so the highest penalty will be
incurred on writes when secrets are created or updated.  In multi-tenant Kube
clusters secrets tend to have the highest load factor (there are 20-40 resources
types per namespace, but most resources only have 1 instance where secrets might
have 3-9 instances across 10k namespaces).  Writes are uncommon, creates usually
happen only when a namespace is created, and reads are somewhat common.

### Actionable Items / Milestones

* [p0] Add ValueTransformer to storage (https://github.com/kubernetes/kubernetes/pull/41939)
* [p0] Create a default implementation of AES-GCM interface (https://github.com/kubernetes/kubernetes/pull/41939)
* [p0] Add encryption flags on kube-apiserver and key rotation API
* [p1] Add kubectl command to call /rotate endpoint
* [p1] Audit of default implementation for safety and security
* [p2] E2E and performance testing
* [p2] Documentation and users guide
* [p2] Read cache layer if encrypting/decrypting Secrets adds too much load on kube-apiserver

# Alternatives Considered

## Encrypting the entire etcd database

Pros:

 - Removes the complexity of deciding which types of things should be encrypted
   in the database.
 - Protects other sensitive configuration and proprietary information that might
   be exposed if etcd backups are made public accidentally.

Cons:

 - Unknown, but likely significant performance impact. If it isn't fast enough
   you don't get to fall back on only encrypting the really important stuff.
   As a counter argument: Docker [implemented their encryption at this
   layer](https://docs.docker.com/engine/swarm/swarm_manager_locking/) and have
   been happy with the performance.


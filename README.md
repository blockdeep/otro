# Otro Pallet

The Otro Pallet provides a Substrate-native implementation of smart accounts.

A Smart Account, in this context, is a Substrate account that can be controlled through various aliases, each associated with a unique public key. 
This allows users to sign transactions using any registered alias. For instance, you could receive assets on a Substrate address and spend them using an Ethereum, RSA, or BLS signature. This versatility is what Otro enables.

Key functionalities:
- Generation of smart accounts from owner accounts.
- Registration and management of credentials.
- Verification of transactions signed with either owner or aliases.

## Supported Signatures Schemas

Currently, the pallet supports the following signature schemas:
- **SR25519**
- **ED25519**
- **ECDSA**
- **Ethereum**
- **BLS** only if the `bls` feature is enabled.
- **RSA** only if the `rsa` feature is enabled.

Note: In all cases the payload is hashed with the `blake2_256` algorithm, except in Ethereum, which uses `keccak256`.

## Integration

To integrate the `Otro` pallet with your runtime, you need to redefine the signature type used in your blockchain.
Replace the default Substrate signature with `NativeOrSmartSignature` to enable compatibility with both native and smart signatures.
Modify your runtime as follows:

```rust
use sp_runtime::MultiSignature;
use sp_runtime::traits::{IdentifyAccount, Verify};
use pallet_otro::{SmartCredentialsProvider, NativeOrSmartSignature};

pub struct Runtime;  // your defined runtime

pub type NativeSignature = MultiSignature;  // or any other native signature type
pub type AccountId = <<NativeSignature as Verify>::Signer as IdentifyAccount>::AccountId;

pub type Signature = NativeOrSmartSignature<
    SmartCredentialsProvider<Runtime>,
    NativeSignature,
>;
```

You will also need to add the `pallet_otro` to your runtime.

## License

The code within this repository is licensed under Apache-2.0 license. See the [LICENSE](./LICENSE) file for more
details.

# Account Abstraction Pallet

The Account Abstraction Pallet provides mechanisms for handling native and abstract signature verification, allowing for more flexible account management.
This pallet introduces support for various signature types and credential management, enhancing security and enabling multi-signature scenarios.

## Overview

The pallet allows accounts to use both native signatures (e.g., Ed25519, Sr25519, ECDSA) and abstract signatures.
Abstract signatures can involve custom signature methods, enabling enhanced account management scenarios, such as integration with custom wallets or smart contract-based accounts.

Key functionalities provided by this pallet include:
- Generation of abstract accounts from native accounts.
- Registration and management of credentials for accounts.
- Verification of transactions signed with either native or abstract signatures.

## Supported signatures schemas

Currently, the pallet supports the following signature schemas:
- **SR25519**
- **ED25519**
- **ECDSA**
- **Ethereum**
- **BLS** only if the `bls` feature is enabled.

Bear in mind that in all cases the payload is expected to be hashed with the `blake2_256` algorithm.

## Key Concepts

### Native and Abstract Signatures

- **Native Signature:** A traditional cryptographic signature using common algorithms like Ed25519, Sr25519, and ECDSA.
- **Abstract Signature:** A signature that includes additional custom logic or cryptographic methods. It consists of a public key and the actual signature, supporting various custom signature types.

### Credential Management

Credentials represent public keys and associated configurations that define how an account can be accessed or managed.
The pallet allows linking multiple credentials to a single account, enabling complex access management scenarios.

### Storage Items

- `Credentials`: A storage double map that holds credentials associated with accounts.
Each credential consists of a public key and a configuration detailing the allowed operations and signature types.

## Integration

To integrate the `Account Abstraction` pallet with your runtime, you need to redefine the signature type used in your blockchain.
Replace the default Substrate signature with `NativeOrAbstractSignature` to enable compatibility with both native and abstract signatures.
Modify your runtime as follows:

```rust
use sp_runtime::MultiSignature;
use sp_runtime::traits::{IdentifyAccount, Verify};
use pallet_account_abstraction::{AbstractCredentialProvider, NativeOrAbstractSignature};

pub struct Runtime;  // your defined runtime

pub type NativeSignature = MultiSignature;  // or any other native signature type
pub type AccountId = <<NativeSignature as Verify>::Signer as IdentifyAccount>::AccountId;

pub type Signature = NativeOrAbstractSignature<
    AbstractCredentialProvider<Runtime>,
    NativeSignature,
>;
```

You will also have to add the `pallet_account_abstraction` to your runtime.

### Regarding MacOS users

If the `bls` feature is enabled, you will need to use a different version of clang, since the OS-provided one cannot compile for wasm. To do so follow these steps:

```shell
# Install LLVM Clang
brew install llvm

# Verify the installation
llvm-config --version

# Export the correct PATH
echo 'export PATH="/opt/homebrew/opt/llvm/bin:$PATH"' >> ~/.zshrc
```

## Security Considerations

- **Signature Verification:** Both native and abstract signatures undergo strict verification to ensure their validity. This protects against unauthorized transactions.
- **Access Control:** Only authorized public keys, as defined in the credential configuration, can interact with an account. This ensures that account operations remain secure.
- **Replay Protection:** Using nonces or similar mechanisms prevents replay attacks, ensuring each transaction is unique and cannot be reused maliciously.

## Future Enhancements

Future versions of the pallet could support:
- More complex credential types, such as biometric authentication or hardware key integration.
- Enhanced user interfaces for managing credentials and abstract accounts.
- Smart contract-based accounts that leverage abstract signatures for more sophisticated transaction logic.

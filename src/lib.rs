//! # Smart Accounts Pallet
//!
//! The Smart Accounts Pallet provides mechanisms for handling native and smart signature verification, allowing for more flexible account management. This pallet introduces support for various signature types and credential management, enhancing security and enabling multi-signature scenarios.
//!
//! ## Overview
//!
//! The pallet allows accounts to use both native signatures (e.g., Ed25519, Sr25519, ECDSA, Ethereum) and smart signatures. Smart signatures can involve custom signature methods, enabling enhanced account management scenarios, such as integration with custom wallets or smart contract-based accounts.
//!
//! Key functionalities provided by this pallet include:
//! - Generation of smart accounts from native accounts.
//! - Registration and management of credentials for accounts.
//! - Verification of transactions signed with either native or smart signatures.
//!
//! ## Key Concepts
//!
//! ### Native and Smart Signatures
//!
//! - **Native Signature:** A traditional cryptographic signature using common algorithms like Ed25519, Sr25519, ECDSA and Ethereum.
//! - **Smart Signature:** A signature that includes additional custom logic or cryptographic methods.
//!   It consists of a public key and the actual signature, supporting various custom signature types.
//!
//! ### Credential Management
//!
//! Credentials represent public keys and associated configurations that define how an account can be accessed or managed.
//! The pallet allows linking multiple credentials to a single account, enabling complex access management scenarios.
//!
//! ### Storage Items
//!
//! - `Credentials`: A storage double map that holds credentials associated with accounts.
//!   Each credential consists of a public key and a configuration detailing the allowed operations and signature types.
//!
//! ## Integration
//!
//! To integrate the `Smart Accounts` pallet with your runtime, you need to redefine the signature type used in your blockchain.
//! Replace the default Substrate signature with `NativeOrSmartSignature` to enable compatibility with both native and smart signatures.
//! Modify your runtime as follows:
//!
//! ```rust
//! use sp_runtime::MultiSignature;
//! use sp_runtime::traits::{IdentifyAccount, Verify};
//! use pallet_smart_accounts::{SmartCredentialsProvider, NativeOrSmartSignature};
//!
//! pub struct Runtime;  // your defined runtime
//!
//! pub type NativeSignature = MultiSignature;  // or any other native signature type
//! pub type AccountId = <<NativeSignature as Verify>::Signer as IdentifyAccount>::AccountId;
//!
//! pub type Signature = NativeOrSmartSignature<
//!     SmartCredentialsProvider<Runtime>,
//!     NativeSignature,
//! >;
//! ```
//!
//! You will also have to add the `pallet_smart_accounts` to your runtime.
//!
//! ## Security Considerations
//!
//! - **Signature Verification:** Both native and smart signatures undergo strict verification to ensure their validity. This protects against unauthorized transactions.
//! - **Access Control:** Only authorized public keys, as defined in the credential configuration, can interact with an account. This ensures that account operations remain secure.
//! - **Replay Protection:** Using nonces or similar mechanisms prevents replay attacks, ensuring each transaction is unique and cannot be reused maliciously.
//!
//! ## Future Enhancements
//!
//! Future versions of the pallet could support:
//! - More complex credential types, such as biometric authentication or hardware key integration.
//! - Enhanced user interfaces for managing credentials and smart accounts.
//! - Smart contract-based accounts that leverage smart signatures for more sophisticated transaction logic.

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;
pub use signature::*;
pub use weights::*;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

pub mod signature;
pub mod weights;

#[frame_support::pallet]
pub mod pallet {
	use frame_support::pallet_prelude::*;
	use frame_support::sp_runtime::traits::Zero;
	use frame_system::pallet_prelude::*;
	use parity_scale_codec::Encode;
	use sha3::{Digest, Keccak256};
	use sp_core::hexdisplay::AsBytesRef;
	use sp_core::{ecdsa, ed25519, sr25519, ByteArray};
	use sp_io::crypto::{ecdsa_verify, ed25519_verify, sr25519_verify};
	use sp_io::hashing::blake2_256;
	use sp_runtime::traits::BlockNumberProvider;
	use sp_std::vec::Vec;

	use super::*;

	const ETHEREUM_ADDRESS_LENGTH: usize = 20;

	/// Signing schemas accepted by this pallet.
	#[derive(Clone, Debug, Encode, Decode, PartialEq, Eq, TypeInfo, MaxEncodedLen)]
	pub enum CredentialType {
		/// An ED25519 signature.
		Ed25519,
		/// An SR25519 signature.
		Sr25519,
		/// An ECDSA signature.
		Ecdsa,
		/// An Ethereum signature or address.
		Ethereum,
		#[cfg(feature = "bls")]
		/// A BLS signature.
		Bls,
		#[cfg(feature = "rsa")]
		/// A RSA signature.
		Rsa,
	}

	/// A credential configuration. Valid for a particular association of an AccountId with
	/// a public key.
	#[derive(Clone, Debug, Encode, Decode, PartialEq, Eq, TypeInfo, MaxEncodedLen)]
	pub struct CredentialConfig {
		pub cred_type: CredentialType,
	}

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config {
		/// The aggregated event type of the runtime.
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

		/// Bytes to be included as entropy when generating smart accounts.
		#[pallet::constant]
		type SignaturePrelude: Get<[u8; 8]>;

		/// The maximum length of a public key, in bytes.
		type MaxPublicKeySize: Get<u32>;

		/// Type representing the weight of this pallet.
		type WeightInfo: WeightInfo;
	}

	/// An AccountId - Public key mapping. Stores the relevant configuration for the association.
	#[pallet::storage]
	pub type Credentials<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		T::AccountId, // smart account
		Blake2_128Concat,
		BoundedVec<u8, T::MaxPublicKeySize>, // public key that is allowed to access the account
		CredentialConfig,
		OptionQuery,
	>;

	#[pallet::error]
	pub enum Error<T> {
		/// An error occurred while generating a smart account.
		SmartAccountGenerationError,
		/// Supplied credentials not found.
		CredentialDoesNotExist,
		/// Public key length does not match the expected one.
		InvalidPublicKeyLength,
		/// The public key is not valid.
		InvalidPublicKey,
		/// The signature is invalid for the given payload.
		InvalidSignature,
		/// Insufficient number of credentials supplied.
		TooFewCredentials,
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A new smart account was generated.
		SmartAccountGenerated { account: T::AccountId, generator: T::AccountId },
		/// A new credential was registered.
		CredentialRegistered {
			account: T::AccountId,
			public_key: BoundedVec<u8, T::MaxPublicKeySize>,
			config: CredentialConfig,
		},
		/// A credential was removed.
		CredentialUnregistered {
			account: T::AccountId,
			public_key: BoundedVec<u8, T::MaxPublicKeySize>,
		},
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn integrity_test() {
			Self::do_try_state().expect("Failure performing the integrity test");
		}

		#[cfg(feature = "try-runtime")]
		fn try_state(_: BlockNumberFor<T>) -> Result<(), sp_runtime::TryRuntimeError> {
			Self::do_try_state()
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Generates a new account and registers a set of credentials for it.
		///
		/// This function is called by an existing account to create a new smart account
		/// derived from its own entropy. The newly generated account is linked with the
		/// provided credentials, which define public keys and their associated configuration.
		///
		/// # Arguments
		/// - `origin`: The account initiating the request, which must be a signed origin.
		/// - `credentials`: A vector of tuples, where each tuple consists of:
		///   - `BoundedVec<u8, MaxPublicKeySize>`: A bounded vector representing the public key.
		///   - `CredentialConfig`: The configuration associated with the public key, which specifies the credential type.
		///
		/// # Errors
		/// - `TooFewCredentials` if the provided credentials vector is empty.
		/// - Fails if the account cannot be generated from the given entropy.
		///
		/// # Usage
		/// A user can call this function to generate a new account and register multiple
		/// credentials with different public keys, allowing them to use those credentials
		/// to access the account.
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::generate_account(credentials.len() as u32))]
		pub fn generate_account(
			origin: OriginFor<T>,
			credentials: Vec<(BoundedVec<u8, T::MaxPublicKeySize>, CredentialConfig)>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			ensure!(!credentials.len().is_zero(), Error::<T>::TooFewCredentials);

			let new_account = Self::generate_account_from_entropy(&who)?;
			Self::deposit_event(Event::SmartAccountGenerated {
				account: new_account.clone(),
				generator: who.clone(),
			});
			for (public_key, config) in credentials {
				Self::do_register_credential(&new_account, public_key, config)?;
			}
			Ok(())
		}

		/// Registers a set of credentials for an existing account.
		///
		/// This function allows an existing account to add new credentials, associating
		/// additional public keys and configurations with the account. This enhances the
		/// account's flexibility by enabling different authentication methods.
		///
		/// # Arguments
		/// - `origin`: The account initiating the request, which must be a signed origin.
		/// - `credentials`: A vector of tuples, where each tuple consists of:
		///   - `BoundedVec<u8, MaxPublicKeySize>`: A bounded vector representing the public key.
		///   - [`CredentialConfig`]: The configuration associated with the public key, specifying the credential type.
		///
		/// # Errors
		/// - `TooFewCredentials` if the provided credentials vector is empty.
		///
		/// # Usage
		/// An account holder can call this function to register new public keys and configurations,
		/// effectively adding more ways to authenticate as this account. This is useful for scenarios
		/// where multi-signature access is required or different authentication methods are needed.
		#[pallet::call_index(1)]
		#[pallet::weight(T::WeightInfo::register_credentials(credentials.len() as u32))]
		pub fn register_credentials(
			origin: OriginFor<T>,
			credentials: Vec<(BoundedVec<u8, T::MaxPublicKeySize>, CredentialConfig)>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			ensure!(!credentials.len().is_zero(), Error::<T>::TooFewCredentials);

			for (public_key, config) in credentials {
				Self::do_register_credential(&who, public_key, config)?;
			}
			Ok(())
		}

		/// Unregisters a specific credential from an account.
		///
		/// This function removes a specified public key from the account's list of registered
		/// credentials. The credential must exist for the operation to succeed.
		///
		/// # Arguments
		/// - `origin`: The account initiating the request, which must be a signed origin.
		/// - `public_key`: A bounded vector representing the public key to be unregistered.
		///
		/// # Errors
		/// - `CredentialDoesNotExist` if the specified public key is not registered with the account.
		///
		/// # Usage
		/// If an account holder decides that a certain public key should no longer have access
		/// to the account, they can call this function to remove that key from the list of registered
		/// credentials. This ensures that only authorized keys are allowed to access the account.
		#[pallet::call_index(2)]
		#[pallet::weight(T::WeightInfo::unregister_credential())]
		pub fn unregister_credential(
			origin: OriginFor<T>,
			public_key: BoundedVec<u8, T::MaxPublicKeySize>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			Credentials::<T>::mutate_exists(
				who.clone(),
				public_key.clone(),
				|maybe_credential| -> DispatchResult {
					ensure!(maybe_credential.is_some(), Error::<T>::CredentialDoesNotExist);
					Self::deposit_event(Event::CredentialUnregistered { account: who, public_key });
					*maybe_credential = None;

					Ok(())
				},
			)
		}
	}

	impl<T: Config> Pallet<T> {
		pub(crate) fn generate_account_from_entropy(
			generator: &T::AccountId,
		) -> Result<T::AccountId, DispatchError> {
			let genesis_hash = frame_system::Pallet::<T>::block_hash(BlockNumberFor::<T>::zero());
			let current_block_number = frame_system::Pallet::<T>::current_block_number();
			let current_block_hash = frame_system::Pallet::<T>::block_hash(current_block_number);
			let extrinsic_index = frame_system::Pallet::<T>::extrinsic_index().unwrap_or(0);
			let nonce = frame_system::Pallet::<T>::account_nonce(generator);

			let full: Vec<u8> = T::SignaturePrelude::get()
				.into_iter()
				.chain(generator.encode())
				.chain(nonce.encode())
				.chain(genesis_hash.encode())
				.chain(current_block_hash.encode())
				.chain(extrinsic_index.encode())
				.collect();

			// This method generates sufficient entropy to create arbitrary AccountId lengths.
			let mut acc_bytes = blake2_256(full.as_slice()).to_vec();
			while acc_bytes.len() < T::AccountId::max_encoded_len() {
				let hash = blake2_256(acc_bytes.as_slice());
				acc_bytes.extend_from_slice(&hash[..]);
			}
			let generated_acc = T::AccountId::decode(&mut &acc_bytes[..])
				// Still, raise an error if something goes wrong.
				.map_err(|_| Error::<T>::SmartAccountGenerationError)?;
			Ok(generated_acc)
		}

		fn do_register_credential(
			who: &T::AccountId,
			public_key: BoundedVec<u8, T::MaxPublicKeySize>,
			config: CredentialConfig,
		) -> DispatchResult {
			ensure!(
				public_key.len() <= T::MaxPublicKeySize::get() as usize,
				Error::<T>::InvalidPublicKeyLength
			);
			let public_key = match config.cred_type {
				CredentialType::Ed25519 => {
					ensure!(
						public_key.len() == ed25519::PUBLIC_KEY_SERIALIZED_SIZE,
						Error::<T>::InvalidPublicKeyLength
					);
					ed25519::Public::try_from(public_key.as_slice())
						.map_err(|_| Error::<T>::InvalidPublicKey)?
						.to_vec()
				},
				CredentialType::Sr25519 => {
					ensure!(
						public_key.len() == sr25519::PUBLIC_KEY_SERIALIZED_SIZE,
						Error::<T>::InvalidPublicKeyLength
					);
					sr25519::Public::try_from(public_key.as_slice())
						.map_err(|_| Error::<T>::InvalidPublicKey)?
						.to_vec()
				},
				CredentialType::Ecdsa => {
					ensure!(
						public_key.len() == ecdsa::PUBLIC_KEY_SERIALIZED_SIZE,
						Error::<T>::InvalidPublicKeyLength
					);
					let public = ecdsa::Public::try_from(public_key.as_slice())
						.map_err(|_| Error::<T>::InvalidPublicKey)?;
					libsecp256k1::PublicKey::parse_slice(public.as_slice(), None)
						.map_err(|_| Error::<T>::InvalidPublicKey)?;
					public.to_vec()
				},
				CredentialType::Ethereum => {
					match public_key.len() {
						ecdsa::PUBLIC_KEY_SERIALIZED_SIZE => {
							let public = ecdsa::Public::try_from(public_key.as_slice())
								.map_err(|_| Error::<T>::InvalidPublicKey)?;
							libsecp256k1::PublicKey::parse_slice(public.as_slice(), None)
								.map_err(|_| Error::<T>::InvalidPublicKey)?;
							public.to_vec()
						},
						// we admit pure Ethereum addresses, which can be derived from ECDSA public keys
						ETHEREUM_ADDRESS_LENGTH => public_key.to_vec(),
						_ => return Err(Error::<T>::InvalidPublicKeyLength.into()),
					}
				},
				#[cfg(feature = "bls")]
				CredentialType::Bls => {
					let public = blst::min_pk::PublicKey::deserialize(public_key.as_slice())
						.map_err(|_| Error::<T>::InvalidPublicKey)?;
					public.serialize().as_slice().to_vec()
				},
				#[cfg(feature = "rsa")]
				CredentialType::Rsa => {
					use rsa::pkcs8::{DecodePublicKey, EncodePublicKey};
					let public = rsa::RsaPublicKey::from_public_key_der(public_key.as_slice())
						.map_err(|_| Error::<T>::InvalidPublicKey)?;
					public
						.to_public_key_der()
						.map_err(|_| Error::<T>::InvalidPublicKey)?
						.as_bytes()
						.to_vec()
				},
			};
			let truncated_public_key = BoundedVec::truncate_from(public_key);
			Credentials::<T>::insert(who, truncated_public_key.clone(), config.clone());
			Self::deposit_event(Event::CredentialRegistered {
				account: who.clone(),
				public_key: truncated_public_key,
				config,
			});
			Ok(())
		}

		fn do_try_state() -> Result<(), sp_runtime::TryRuntimeError> {
			ensure!(T::MaxPublicKeySize::get() >= 128, "The minimum signature length is 128 bytes");
			Ok(())
		}

		pub(crate) fn check_smart_signature(
			account: &T::AccountId,
			public_key_bytes: &[u8],
			signature_bytes: &[u8],
			payload: &[u8],
		) -> Result<(), DispatchError> {
			let config = Credentials::<T>::get(
				account,
				BoundedVec::truncate_from(public_key_bytes.to_vec()),
			)
			.ok_or(Error::<T>::CredentialDoesNotExist)?;
			let verified = match config.cred_type {
				CredentialType::Ed25519 => {
					let signature = ed25519::Signature::try_from(signature_bytes)
						.map_err(|_| Error::<T>::InvalidSignature)?;
					let public_key = ed25519::Public::try_from(public_key_bytes)
						.map_err(|_| Error::<T>::InvalidPublicKey)?;
					ed25519_verify(&signature, payload, &public_key)
				},
				CredentialType::Sr25519 => {
					let signature = sr25519::Signature::try_from(signature_bytes)
						.map_err(|_| Error::<T>::InvalidSignature)?;
					let public_key = sr25519::Public::try_from(public_key_bytes)
						.map_err(|_| Error::<T>::InvalidPublicKey)?;
					sr25519_verify(&signature, payload, &public_key)
				},
				CredentialType::Ecdsa => {
					let signature = ecdsa::Signature::try_from(signature_bytes)
						.map_err(|_| Error::<T>::InvalidSignature)?;
					let public_key = ecdsa::Public::try_from(public_key_bytes)
						.map_err(|_| Error::<T>::InvalidPublicKey)?;
					ecdsa_verify(&signature, payload, &public_key)
				},
				CredentialType::Ethereum => {
					let signature = ecdsa::Signature::try_from(signature_bytes)
						.map_err(|_| Error::<T>::InvalidSignature)?;
					// Use the keccak256 hashing algorithm here and then verify with plain ECDSA.
					let mut hash = [0u8; 32];
					hash.copy_from_slice(Keccak256::digest(payload).as_slice());
					let computed_public_key =
						signature.recover_prehashed(&hash).ok_or(Error::<T>::InvalidSignature)?;
					match public_key_bytes.len() {
						ecdsa::PUBLIC_KEY_SERIALIZED_SIZE => {
							computed_public_key.as_bytes_ref() == public_key_bytes
						},
						ETHEREUM_ADDRESS_LENGTH => {
							let ethereum_address =
								Keccak256::digest(computed_public_key)[12..].to_vec();
							ethereum_address.as_slice() == public_key_bytes
						},
						_ => false,
					}
				},
				#[cfg(feature = "bls")]
				CredentialType::Bls => {
					let signature = blst::min_pk::Signature::deserialize(signature_bytes)
						.map_err(|_| Error::<T>::InvalidSignature)?;
					let public_key = blst::min_pk::PublicKey::deserialize(public_key_bytes)
						.map_err(|_| Error::<T>::InvalidPublicKey)?;
					let err = signature.verify(true, payload, &[], &[], &public_key, true);
					err == blst::BLST_ERROR::BLST_SUCCESS
				},
				#[cfg(feature = "rsa")]
				CredentialType::Rsa => {
					use rsa::pkcs8::DecodePublicKey;
					use rsa::signature::Verifier;

					let public_key = rsa::RsaPublicKey::from_public_key_der(public_key_bytes)
						.map_err(|_| Error::<T>::InvalidPublicKey)?;
					let verifying_key =
						rsa::pss::VerifyingKey::<blake2::Blake2s256>::new(public_key);
					let signature = rsa::pss::Signature::try_from(signature_bytes)
						.map_err(|_| Error::<T>::InvalidSignature)?;
					verifying_key.verify(payload, &signature).is_ok()
				},
			};
			ensure!(verified, Error::<T>::InvalidSignature);
			Ok(())
		}
	}
}

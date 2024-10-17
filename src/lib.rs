//! # Account Abstraction Pallet
//!
//! The Account Abstraction Pallet provides mechanisms for handling native and abstract signature verification, allowing for more flexible account management. This pallet introduces support for various signature types and credential management, enhancing security and enabling multi-signature scenarios.
//!
//! ## Overview
//!
//! The pallet allows accounts to use both native signatures (e.g., Ed25519, Sr25519, ECDSA) and abstract signatures. Abstract signatures can involve custom signature methods, enabling enhanced account management scenarios, such as integration with custom wallets or smart contract-based accounts.
//!
//! Key functionalities provided by this pallet include:
//! - Generation of abstract accounts from native accounts.
//! - Registration and management of credentials for accounts.
//! - Verification of transactions signed with either native or abstract signatures.
//!
//! ## Key Concepts
//!
//! ### Native and Abstract Signatures
//!
//! - **Native Signature:** A traditional cryptographic signature using common algorithms like Ed25519, Sr25519, and ECDSA.
//! - **Abstract Signature:** A signature that includes additional custom logic or cryptographic methods.
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
//! To integrate the `Account Abstraction` pallet with your runtime, you need to redefine the signature type used in your blockchain.
//! Replace the default Substrate signature with `NativeOrAbstractSignature` to enable compatibility with both native and abstract signatures.
//! Modify your runtime as follows:
//!
//! ```rust
//! use sp_runtime::MultiSignature;
//! use pallet_account_abstraction::{AbstractCredentialProvider, NativeOrAbstractSignature};
//! struct Runtime;  // your defined runtime
//!
//! type NativeSignature = MultiSignature;  // or any other native signature type
//! type Signature = NativeOrAbstractSignature<
//!     AbstractCredentialProvider<Runtime>,
//!     NativeSignature,
//! >;
//! ```
//!
//! You will also have to add the `pallet_account_abstraction` to your runtime.
//!
//! ## Security Considerations
//!
//! - **Signature Verification:** Both native and abstract signatures undergo strict verification to ensure their validity. This protects against unauthorized transactions.
//! - **Access Control:** Only authorized public keys, as defined in the credential configuration, can interact with an account. This ensures that account operations remain secure.
//! - **Replay Protection:** Using nonces or similar mechanisms prevents replay attacks, ensuring each transaction is unique and cannot be reused maliciously.
//!
//! ## Future Enhancements
//!
//! Future versions of the pallet could support:
//! - More complex credential types, such as biometric authentication or hardware key integration.
//! - Enhanced user interfaces for managing credentials and abstract accounts.
//! - Smart contract-based accounts that leverage abstract signatures for more sophisticated transaction logic.

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
	use sp_core::{ecdsa, ed25519, sr25519, ByteArray};
	use sp_io::crypto::{ecdsa_verify, ed25519_verify, sr25519_verify};
	use sp_io::hashing::blake2_256;
	use sp_runtime::traits::BlockNumberProvider;
	use sp_std::vec::Vec;

	use super::*;

	/// Signing schemas accepted by this pallet.
	#[derive(Clone, Debug, Encode, Decode, PartialEq, Eq, TypeInfo, MaxEncodedLen)]
	pub enum CredentialType {
		/// An ED25519 signature.
		Ed25519,
		/// An SR25519 signature.
		Sr25519,
		/// An ECDSA signature.
		Ecdsa,
	}

	/// A credential configuration. Valid for a particular association of an AccountId with
	/// a public key.
	#[derive(Clone, Debug, Encode, Decode, PartialEq, Eq, TypeInfo, MaxEncodedLen)]
	pub struct CredentialConfig {
		pub cred_type: CredentialType,
	}

	/// The maximum length of a public key. Whenever new public key types are added
	/// this value must be increased if needed.
	pub struct MaxPublicKeySize;
	impl Get<u32> for MaxPublicKeySize {
		fn get() -> u32 {
			128
		}
	}

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config {
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

		/// Bytes to be included as entropy when generating abstract accounts.
		#[pallet::constant]
		type SignaturePrelude: Get<[u8; 8]>;

		/// Type representing the weight of this pallet.
		type WeightInfo: WeightInfo;
	}

	/// An AccountId - Public key mapping. Stores the relevant configuration for the association.
	#[pallet::storage]
	pub type Credentials<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		T::AccountId, // abstract account
		Blake2_128Concat,
		BoundedVec<u8, MaxPublicKeySize>, // public key that is allowed to access the account
		CredentialConfig,
		OptionQuery,
	>;

	#[pallet::error]
	pub enum Error<T> {
		/// An error occurred while generating an abstract account.
		AccountGenerationError,
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
		/// A new abstract account was generated.
		AccountGenerated { account: T::AccountId, generator: T::AccountId },
		/// A new credential was registered.
		CredentialRegistered {
			account: T::AccountId,
			public_key: BoundedVec<u8, MaxPublicKeySize>,
			config: CredentialConfig,
		},
		/// A credential was removed.
		CredentialUnregistered {
			account: T::AccountId,
			public_key: BoundedVec<u8, MaxPublicKeySize>,
		},
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Generates a new account and registers a set of credentials for it.
		///
		/// This function is called by an existing account to create a new abstract account
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
			credentials: Vec<(BoundedVec<u8, MaxPublicKeySize>, CredentialConfig)>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			ensure!(!credentials.len().is_zero(), Error::<T>::TooFewCredentials);

			let new_account = Self::generate_account_from_entropy(&who)?;
			Self::deposit_event(Event::AccountGenerated {
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
			credentials: Vec<(BoundedVec<u8, MaxPublicKeySize>, CredentialConfig)>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			ensure!(!credentials.len().is_zero(), Error::<T>::TooFewCredentials);

			for (public_key, config) in credentials {
				// TODO charge fee?
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
			public_key: BoundedVec<u8, MaxPublicKeySize>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			Credentials::<T>::mutate_exists(
				who.clone(),
				public_key.clone(),
				|maybe_credential| -> DispatchResult {
					ensure!(maybe_credential.is_some(), Error::<T>::CredentialDoesNotExist);
					Self::deposit_event(Event::CredentialUnregistered { account: who, public_key });
					// TODO release fee?
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
				.map_err(|_| Error::<T>::AccountGenerationError)?;
			Ok(generated_acc)
		}

		fn do_register_credential(
			who: &T::AccountId,
			public_key: BoundedVec<u8, MaxPublicKeySize>,
			config: CredentialConfig,
		) -> DispatchResult {
			ensure!(
				public_key.len() <= MaxPublicKeySize::get() as usize,
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

		pub(crate) fn check_abstract_signature(
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
			};
			ensure!(verified, Error::<T>::InvalidSignature);
			Ok(())
		}
	}
}

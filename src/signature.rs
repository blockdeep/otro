// Copyright (C) BlockDeep Labs UG.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::{Config, Pallet};
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_runtime::traits::{IdentifyAccount, Lazy, Verify};
use sp_std::marker::PhantomData;
use sp_std::vec::Vec;

pub trait SmartCredential {
	type AccountId;

	fn is_valid(
		public_key: &[u8],
		signature: &[u8],
		account: &Self::AccountId,
		payload: &[u8],
	) -> bool;
}

#[derive(Eq, PartialEq, Clone, Encode, Decode, sp_core::RuntimeDebug, TypeInfo)]
pub struct SmartCredentialsProvider<T>(PhantomData<T>);

impl<T: Config> SmartCredential for SmartCredentialsProvider<T> {
	type AccountId = T::AccountId;

	fn is_valid(
		public_key: &[u8],
		signature: &[u8],
		account: &Self::AccountId,
		payload: &[u8],
	) -> bool {
		Pallet::<T>::check_smart_signature(account, public_key, signature, payload).is_ok()
	}
}

#[derive(Eq, PartialEq, Clone, Encode, Decode, sp_core::RuntimeDebug, TypeInfo)]
pub enum NativeOrSmartSignature<Credential, NativeSignature> {
	Native(NativeSignature),
	// public key | signature
	Smart(Vec<u8>, Vec<u8>, PhantomData<Credential>),
}

impl<Credential, NativeSignature> From<NativeSignature>
	for NativeOrSmartSignature<Credential, NativeSignature>
{
	fn from(signature: NativeSignature) -> Self {
		Self::Native(signature)
	}
}

impl<Credential, NativeSignature> NativeOrSmartSignature<Credential, NativeSignature> {
	pub fn new_native(signature: NativeSignature) -> Self {
		Self::Native(signature)
	}

	pub fn new_smart(public_key: Vec<u8>, signature: Vec<u8>) -> Self {
		Self::Smart(public_key, signature, PhantomData)
	}
}

impl<Credential, NativeSignature> Verify for NativeOrSmartSignature<Credential, NativeSignature>
where
	NativeSignature: Verify,
	Credential:
		SmartCredential<AccountId = <NativeSignature::Signer as IdentifyAccount>::AccountId>,
{
	type Signer = NativeSignature::Signer;

	fn verify<L: Lazy<[u8]>>(
		&self,
		mut msg: L,
		signer: &<Self::Signer as IdentifyAccount>::AccountId,
	) -> bool {
		match self {
			Self::Native(native_signature) => native_signature.verify(msg, signer),
			Self::Smart(public_key, signature, _) => {
				Credential::is_valid(public_key.as_slice(), signature.as_slice(), signer, msg.get())
			},
		}
	}
}

#[cfg(test)]
mod tests {
	use sha3::{Digest, Keccak256};
	use super::*;
	use crate::mock::*;
	use crate::{CredentialConfig, CredentialType};
	use sp_core::{ecdsa, sr25519};
	use sp_io::crypto::{ecdsa_generate, ecdsa_sign_prehashed, sr25519_generate, sr25519_sign};
	use sp_runtime::{MultiSignature, MultiSigner};

	type TestCredentialProvider = SmartCredentialsProvider<Test>;

	#[test]
	fn native_or_smart_signature_conversion_should_work() {
		let native_signature = MultiSignature::Sr25519(Default::default());

		let native_or_smart_signature_1: NativeOrSmartSignature<
			TestCredentialProvider,
			MultiSignature,
		> = native_signature.clone().into();
		assert_eq!(
			native_or_smart_signature_1,
			NativeOrSmartSignature::Native(native_signature.clone())
		);

		let native_or_smart_signature_2: NativeOrSmartSignature<TestCredentialProvider, _> =
			NativeOrSmartSignature::new_native(native_signature.clone());
		assert_eq!(
			native_or_smart_signature_2,
			NativeOrSmartSignature::Native(native_signature.clone())
		);

		new_test_ext().execute_with(|| {
			let public: sr25519::Public = sr25519_generate(0.into(), None);
			let public_key_bytes = public.encode();
			let payload = [0u8; 32];
			let signature = sr25519_sign(0.into(), &public, &payload).unwrap();
			let native_or_smart_signature_3: NativeOrSmartSignature<
				TestCredentialProvider,
				MultiSignature,
			> = NativeOrSmartSignature::new_smart(public_key_bytes.clone(), signature.to_vec());
			assert_eq!(
				native_or_smart_signature_3,
				NativeOrSmartSignature::Smart(public_key_bytes, signature.to_vec(), PhantomData)
			);
		});
	}

	#[test]
	fn native_or_smart_signature_native_verification_should_work() {
		new_test_ext().execute_with(|| {
			let payload = *b"test ethereum signature";
			let public: sr25519::Public = sr25519_generate(0.into(), None);
			let raw_signature = sr25519_sign(0.into(), &public, &payload).unwrap();

			let native_signer = MultiSigner::Sr25519(public);
			let native_signature = MultiSignature::Sr25519(raw_signature);
			assert!(native_signature.verify(&payload[..], &native_signer.clone().into_account()));

			let native_or_smart_signature: NativeOrSmartSignature<TestCredentialProvider, _> =
				NativeOrSmartSignature::new_native(native_signature);
			let native_or_smart_signer = native_signer.clone();
			assert!(native_or_smart_signature
				.verify(&payload[..], &native_or_smart_signer.into_account()));
		});
	}

	#[test]
	fn native_or_smart_signature_smart_verification_should_work() {
		new_test_ext().execute_with(|| {
			let public: sr25519::Public = sr25519_generate(0.into(), None);
			let public_key_bytes = public.encode();
			let payload = *b"smart verification should work";
			let raw_signature = sr25519_sign(0.into(), &public, &payload).unwrap();

			let native_signer = MultiSigner::Sr25519(public);
			let native_signature = MultiSignature::Sr25519(raw_signature);
			assert!(native_signature.verify(&payload[..], &native_signer.clone().into_account()));

			let caller = native_signer.clone().into_account();
			Otro::generate_account(
				RuntimeOrigin::signed(caller.clone()),
				vec![(
					public_key_bytes.clone().try_into().unwrap(),
					CredentialConfig { cred_type: CredentialType::Sr25519 },
				)],
			)
			.unwrap();
			let created_account = Otro::generate_account_from_entropy(&caller).unwrap();
			let native_or_smart_signature: NativeOrSmartSignature<
				TestCredentialProvider,
				MultiSignature,
			> = NativeOrSmartSignature::new_smart(public_key_bytes.clone(), raw_signature.to_vec());
			assert!(native_or_smart_signature.verify(&payload[..], &created_account));
		});
	}

	#[test]
	fn native_or_smart_signature_smart_verification_with_ethereum_addresses_should_work() {
		new_test_ext().execute_with(|| {
			let public: ecdsa::Public = ecdsa_generate(0.into(), None);
			let public_key_bytes = public.encode();
			let payload = b"smart verification with ethereum addresses should work";
			let mut hash = [0u8; 32];
			hash.copy_from_slice(Keccak256::digest(payload).as_slice());
			let raw_signature = ecdsa_sign_prehashed(0.into(), &public, &hash).unwrap();

			let native_signer = MultiSigner::Ecdsa(public);
			let caller = native_signer.clone().into_account();
			let ethereum_address =
				Keccak256::digest(public_key_bytes)[12..].to_vec();
			Otro::generate_account(
				RuntimeOrigin::signed(caller.clone()),
				vec![(
					ethereum_address.clone().try_into().unwrap(),
					CredentialConfig { cred_type: CredentialType::Ethereum },
				)],
			)
				.unwrap();
			let created_account = Otro::generate_account_from_entropy(&caller).unwrap();
			let native_or_smart_signature: NativeOrSmartSignature<
				TestCredentialProvider,
				MultiSignature,
			> = NativeOrSmartSignature::new_smart(ethereum_address.clone(), raw_signature.to_vec());
			assert!(native_or_smart_signature.verify(&payload[..], &created_account));
		});
	}
}

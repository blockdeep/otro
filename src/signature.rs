use crate::{Config, Pallet};
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_runtime::traits::{IdentifyAccount, Lazy, Verify};
use sp_std::marker::PhantomData;
use sp_std::vec::Vec;

pub trait AbstractCredential {
	type AccountId;

	fn is_valid(
		public_key: &[u8],
		signature: &[u8],
		account: &Self::AccountId,
		payload: &[u8],
	) -> bool;
}

#[derive(Eq, PartialEq, Clone, Encode, Decode, sp_core::RuntimeDebug, TypeInfo)]
pub struct AbstractCredentialProvider<T>(PhantomData<T>);

impl<T: Config> AbstractCredential for AbstractCredentialProvider<T> {
	type AccountId = T::AccountId;

	fn is_valid(
		public_key: &[u8],
		signature: &[u8],
		account: &Self::AccountId,
		payload: &[u8],
	) -> bool {
		Pallet::<T>::check_abstract_signature(account, public_key, signature, payload).is_ok()
	}
}

#[derive(Eq, PartialEq, Clone, Encode, Decode, sp_core::RuntimeDebug, TypeInfo)]
pub enum NativeOrAbstractSignature<Credential, NativeSignature> {
	Native(NativeSignature),
	// public key | signature
	Abstract(Vec<u8>, Vec<u8>, PhantomData<Credential>),
}

impl<Credential, NativeSignature> From<NativeSignature>
	for NativeOrAbstractSignature<Credential, NativeSignature>
{
	fn from(signature: NativeSignature) -> Self {
		Self::Native(signature)
	}
}

impl<Credential, NativeSignature> NativeOrAbstractSignature<Credential, NativeSignature> {
	pub fn new_native(signature: NativeSignature) -> Self {
		Self::Native(signature)
	}

	pub fn new_abstract(public_key: Vec<u8>, signature: Vec<u8>) -> Self {
		Self::Abstract(public_key, signature, PhantomData)
	}
}

impl<Credential, NativeSignature> Verify for NativeOrAbstractSignature<Credential, NativeSignature>
where
	NativeSignature: Verify,
	Credential:
		AbstractCredential<AccountId = <NativeSignature::Signer as IdentifyAccount>::AccountId>,
{
	type Signer = NativeSignature::Signer;

	fn verify<L: Lazy<[u8]>>(
		&self,
		mut msg: L,
		signer: &<Self::Signer as IdentifyAccount>::AccountId,
	) -> bool {
		match self {
			Self::Native(native_signature) => native_signature.verify(msg, signer),
			Self::Abstract(public_key, signature, _) => Credential::is_valid(
				public_key.as_slice(),
				signature.as_slice(),
				&signer,
				msg.get(),
			),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::mock::*;
	use crate::{CredentialConfig, CredentialType};
	use sp_core::sr25519;
	use sp_io::crypto::{sr25519_generate, sr25519_sign};
	use sp_runtime::{MultiSignature, MultiSigner};

	type TestCredentialProvider = AbstractCredentialProvider<Test>;

	#[test]
	fn native_or_abstract_signature_conversion_should_work() {
		let native_signature = MultiSignature::Sr25519(Default::default());

		let native_or_abstract_signature_1: NativeOrAbstractSignature<
			TestCredentialProvider,
			MultiSignature,
		> = native_signature.clone().into();
		assert_eq!(
			native_or_abstract_signature_1,
			NativeOrAbstractSignature::Native(native_signature.clone())
		);

		let native_or_abstract_signature_2: NativeOrAbstractSignature<TestCredentialProvider, _> =
			NativeOrAbstractSignature::new_native(native_signature.clone());
		assert_eq!(
			native_or_abstract_signature_2,
			NativeOrAbstractSignature::Native(native_signature.clone())
		);

		new_test_ext().execute_with(|| {
			let public: sr25519::Public = sr25519_generate(0.into(), None);
			let public_key_bytes = public.encode();
			let payload = [0u8; 32];
			let signature = sr25519_sign(0.into(), &public, &payload).unwrap();
			let native_or_abstract_signature_3: NativeOrAbstractSignature<
				TestCredentialProvider,
				MultiSignature,
			> = NativeOrAbstractSignature::new_abstract(public_key_bytes.clone(), signature.to_vec());
			assert_eq!(
				native_or_abstract_signature_3,
				NativeOrAbstractSignature::Abstract(
					public_key_bytes,
					signature.to_vec(),
					PhantomData
				)
			);
		});
	}

	#[test]
	fn native_or_abstract_signature_native_verification_should_work() {
		new_test_ext().execute_with(|| {
			let payload = [0u8; 32];
			let public: sr25519::Public = sr25519_generate(0.into(), None);
			let raw_signature = sr25519_sign(0.into(), &public, &payload).unwrap();

			let native_signer = MultiSigner::Sr25519(public);
			let native_signature = MultiSignature::Sr25519(raw_signature);
			assert!(native_signature.verify(&payload[..], &native_signer.clone().into_account()));

			let native_or_abstract_signature: NativeOrAbstractSignature<TestCredentialProvider, _> =
				NativeOrAbstractSignature::new_native(native_signature);
			let native_or_abstract_signer = native_signer.clone();
			assert!(native_or_abstract_signature
				.verify(&payload[..], &native_or_abstract_signer.into_account()));
		});
	}

	#[test]
	fn native_or_abstract_signature_abstract_verification_should_work() {
		new_test_ext().execute_with(|| {
			let public: sr25519::Public = sr25519_generate(0.into(), None);
			let public_key_bytes = public.encode();
			let payload = [0u8; 32];
			let raw_signature = sr25519_sign(0.into(), &public, &payload).unwrap();

			let native_signer = MultiSigner::Sr25519(public);
			let native_signature = MultiSignature::Sr25519(raw_signature);
			assert!(native_signature.verify(&payload[..], &native_signer.clone().into_account()));

			let caller = native_signer.clone().into_account();
			AccountAbstraction::generate_account(
				RuntimeOrigin::signed(caller.clone()),
				vec![(
					public_key_bytes.clone().try_into().unwrap(),
					CredentialConfig { cred_type: CredentialType::Sr25519 },
				)],
			)
			.unwrap();
			let created_account =
				AccountAbstraction::generate_account_from_entropy(&caller).unwrap();
			let native_or_abstract_signature: NativeOrAbstractSignature<
				TestCredentialProvider,
				MultiSignature,
			> = NativeOrAbstractSignature::new_abstract(
				public_key_bytes.clone(),
				raw_signature.to_vec(),
			);
			assert!(native_or_abstract_signature.verify(&payload[..], &created_account));
		});
	}
}

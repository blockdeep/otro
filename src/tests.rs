use frame_support::{assert_noop, BoundedVec};
use hex_literal::hex;
use parity_scale_codec::Encode;
use sha3::{Digest, Keccak256};
use sp_core::{ecdsa, ed25519, sr25519, ByteArray};
use sp_io::crypto::{
	ecdsa_generate, ecdsa_sign, ecdsa_sign_prehashed, ed25519_generate, ed25519_sign,
	sr25519_generate, sr25519_sign,
};
use sp_std::collections::btree_set::BTreeSet;

use crate::{
	mock::*, CredentialConfig, CredentialType, Credentials, Error, Event, MaxPublicKeySize,
};

type AccountId = <Test as frame_system::Config>::AccountId;

fn acc(index: u32) -> AccountId {
	match index {
		0 => AccountId::from(hex!(
			"e2f8a6b9d3c1f02e4a5b7c9d8e1f0a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f"
		)),
		1 => AccountId::from(hex!(
			"9a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f0a1b2c3d4e5f6a7b8c9d0e1f2a3b"
		)),
		3 => AccountId::from(hex!(
			"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
		)),
		4 => AccountId::from(hex!(
			"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
		)),
		5 => AccountId::from(hex!(
			"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
		)),
		_ => panic!("Account not registered in tests"),
	}
}

#[test]
fn generate_account() {
	new_test_ext().execute_with(|| {
		initialize_to_block(1);
		let generator = acc(1);
		let mut set = BTreeSet::new();
		// make sure the generated account is not the generator.
		set.insert(generator.clone());
		// first one, generic.
		let acc1 = AccountAbstraction::generate_account_from_entropy(&generator).unwrap();
		set.insert(acc1.clone());
		// should generate the same
		set.insert(AccountAbstraction::generate_account_from_entropy(&generator).unwrap());
		// second one, same block, increasing nonce.
		System::inc_account_nonce(generator.clone());
		let acc2 = AccountAbstraction::generate_account_from_entropy(&generator).unwrap();
		set.insert(acc2.clone());
		assert_eq!(set.len(), 3);
	})
}

#[test]
fn register_credential_ecdsa() {
	new_test_ext().execute_with(|| {
		initialize_to_block(1);
		let owner = acc(1);
		let invalid_public_key = sr25519_generate(0.into(), None);
		let invalid_public_key_bytes: BoundedVec<u8, MaxPublicKeySize> =
			invalid_public_key.encode().try_into().unwrap();

		let public: ecdsa::Public = ecdsa_generate(0.into(), None);
		let public_key_bytes: BoundedVec<u8, MaxPublicKeySize> =
			public.encode().try_into().unwrap();
		assert_eq!(Credentials::<Test>::get(owner.clone(), public_key_bytes.clone()), None);
		assert_noop!(
			AccountAbstraction::register_credentials(
				RuntimeOrigin::signed(owner.clone()),
				vec![(
					public_key_bytes.clone(),
					CredentialConfig { cred_type: CredentialType::Sr25519 },
				)],
			),
			Error::<Test>::InvalidPublicKeyLength
		);
		assert_noop!(
			AccountAbstraction::register_credentials(
				RuntimeOrigin::signed(owner.clone()),
				vec![(
					public_key_bytes.clone(),
					CredentialConfig { cred_type: CredentialType::Ed25519 },
				)],
			),
			Error::<Test>::InvalidPublicKeyLength
		);
		assert_noop!(
			AccountAbstraction::register_credentials(
				RuntimeOrigin::signed(owner.clone()),
				vec![(
					invalid_public_key_bytes.clone(),
					CredentialConfig { cred_type: CredentialType::Ecdsa },
				)],
			),
			Error::<Test>::InvalidPublicKeyLength
		);
		let long_public_key = [0u8; 128].to_vec().try_into().unwrap();
		assert_noop!(
			AccountAbstraction::register_credentials(
				RuntimeOrigin::signed(owner.clone()),
				vec![(long_public_key, CredentialConfig { cred_type: CredentialType::Ecdsa },)],
			),
			Error::<Test>::InvalidPublicKeyLength
		);
		let zero_public_key = [0u8; 33].to_vec().try_into().unwrap();
		assert_noop!(
			AccountAbstraction::register_credentials(
				RuntimeOrigin::signed(owner.clone()),
				vec![(zero_public_key, CredentialConfig { cred_type: CredentialType::Ecdsa },)],
			),
			Error::<Test>::InvalidPublicKey
		);
		AccountAbstraction::register_credentials(
			RuntimeOrigin::signed(owner.clone()),
			vec![(public_key_bytes.clone(), CredentialConfig { cred_type: CredentialType::Ecdsa })],
		)
		.expect("ECDSA credential should be successfully registered");
		assert_eq!(
			Credentials::<Test>::get(owner.clone(), public_key_bytes.clone()),
			Some(CredentialConfig { cred_type: CredentialType::Ecdsa })
		);
		System::assert_last_event(RuntimeEvent::AccountAbstraction(Event::CredentialRegistered {
			account: owner.clone(),
			public_key: public_key_bytes,
			config: CredentialConfig { cred_type: CredentialType::Ecdsa },
		}));
	});
}

#[test]
fn register_credential_sr25519() {
	new_test_ext().execute_with(|| {
		initialize_to_block(1);
		let owner = acc(1);
		let invalid_public_key = ecdsa_generate(0.into(), None);
		let invalid_public_key_bytes: BoundedVec<u8, MaxPublicKeySize> =
			invalid_public_key.encode().try_into().unwrap();

		let public: sr25519::Public = sr25519_generate(0.into(), None);
		let public_key_bytes: BoundedVec<u8, MaxPublicKeySize> =
			public.encode().try_into().unwrap();
		assert_eq!(Credentials::<Test>::get(owner.clone(), public_key_bytes.clone()), None);
		assert_noop!(
			AccountAbstraction::register_credentials(
				RuntimeOrigin::signed(owner.clone()),
				vec![(
					public_key_bytes.clone(),
					CredentialConfig { cred_type: CredentialType::Ecdsa },
				)],
			),
			Error::<Test>::InvalidPublicKeyLength
		);
		// here we cannot test against ED25519, as both SR25519 and ED25519 bytes can be valid.
		assert_noop!(
			AccountAbstraction::register_credentials(
				RuntimeOrigin::signed(owner.clone()),
				vec![(
					invalid_public_key_bytes.clone(),
					CredentialConfig { cred_type: CredentialType::Sr25519 },
				)],
			),
			Error::<Test>::InvalidPublicKeyLength
		);
		let long_public_key = [0u8; 128].to_vec().try_into().unwrap();
		assert_noop!(
			AccountAbstraction::register_credentials(
				RuntimeOrigin::signed(owner.clone()),
				vec![(long_public_key, CredentialConfig { cred_type: CredentialType::Sr25519 },)],
			),
			Error::<Test>::InvalidPublicKeyLength
		);
		let zero_public_key = [0u8; 33].to_vec().try_into().unwrap();
		assert_noop!(
			AccountAbstraction::register_credentials(
				RuntimeOrigin::signed(owner.clone()),
				vec![(zero_public_key, CredentialConfig { cred_type: CredentialType::Sr25519 },)],
			),
			Error::<Test>::InvalidPublicKeyLength
		);
		AccountAbstraction::register_credentials(
			RuntimeOrigin::signed(owner.clone()),
			vec![(
				public_key_bytes.clone(),
				CredentialConfig { cred_type: CredentialType::Sr25519 },
			)],
		)
		.expect("SR25519 credential should be successfully registered");
		assert_eq!(
			Credentials::<Test>::get(owner.clone(), public_key_bytes.clone()),
			Some(CredentialConfig { cred_type: CredentialType::Sr25519 })
		);
		System::assert_last_event(RuntimeEvent::AccountAbstraction(Event::CredentialRegistered {
			account: owner.clone(),
			public_key: public_key_bytes,
			config: CredentialConfig { cred_type: CredentialType::Sr25519 },
		}));
	});
}

#[test]
fn register_credential_ed25519() {
	new_test_ext().execute_with(|| {
		initialize_to_block(1);
		let owner = acc(1);
		let invalid_public_key = ecdsa_generate(0.into(), None);
		let invalid_public_key_bytes: BoundedVec<u8, MaxPublicKeySize> =
			invalid_public_key.encode().try_into().unwrap();

		let public: ed25519::Public = ed25519_generate(0.into(), None);
		let public_key_bytes: BoundedVec<u8, MaxPublicKeySize> =
			public.encode().try_into().unwrap();
		assert_eq!(Credentials::<Test>::get(owner.clone(), public_key_bytes.clone()), None);
		assert_noop!(
			AccountAbstraction::register_credentials(
				RuntimeOrigin::signed(owner.clone()),
				vec![(
					public_key_bytes.clone(),
					CredentialConfig { cred_type: CredentialType::Ecdsa },
				)],
			),
			Error::<Test>::InvalidPublicKeyLength
		);
		// here we cannot test against ED25519, as both SR25519 and ED25519 bytes can be valid.
		assert_noop!(
			AccountAbstraction::register_credentials(
				RuntimeOrigin::signed(owner.clone()),
				vec![(
					invalid_public_key_bytes.clone(),
					CredentialConfig { cred_type: CredentialType::Ed25519 },
				)],
			),
			Error::<Test>::InvalidPublicKeyLength
		);
		let long_public_key = [0u8; 128].to_vec().try_into().unwrap();
		assert_noop!(
			AccountAbstraction::register_credentials(
				RuntimeOrigin::signed(owner.clone()),
				vec![(long_public_key, CredentialConfig { cred_type: CredentialType::Ed25519 },)]
			),
			Error::<Test>::InvalidPublicKeyLength
		);
		let zero_public_key = [0u8; 33].to_vec().try_into().unwrap();
		assert_noop!(
			AccountAbstraction::register_credentials(
				RuntimeOrigin::signed(owner.clone()),
				vec![(zero_public_key, CredentialConfig { cred_type: CredentialType::Ed25519 },)],
			),
			Error::<Test>::InvalidPublicKeyLength
		);
		AccountAbstraction::register_credentials(
			RuntimeOrigin::signed(owner.clone()),
			vec![(
				public_key_bytes.clone(),
				CredentialConfig { cred_type: CredentialType::Ed25519 },
			)],
		)
		.expect("ED25519 credential should be successfully registered");
		assert_eq!(
			Credentials::<Test>::get(owner.clone(), public_key_bytes.clone()),
			Some(CredentialConfig { cred_type: CredentialType::Ed25519 })
		);
		System::assert_last_event(RuntimeEvent::AccountAbstraction(Event::CredentialRegistered {
			account: owner.clone(),
			public_key: public_key_bytes,
			config: CredentialConfig { cred_type: CredentialType::Ed25519 },
		}));
	});
}

#[test]
fn check_abstract_signature_ecdsa() {
	new_test_ext().execute_with(|| {
		initialize_to_block(1);
		let owner = acc(1);
		let public: ecdsa::Public = ecdsa_generate(0.into(), None);
		let public_key_bytes: BoundedVec<u8, MaxPublicKeySize> =
			public.encode().try_into().unwrap();
		AccountAbstraction::register_credentials(
			RuntimeOrigin::signed(owner.clone()),
			vec![(public_key_bytes.clone(), CredentialConfig { cred_type: CredentialType::Ecdsa })],
		)
		.expect("ECDSA public key registration should be valid");
		assert_eq!(
			Credentials::<Test>::get(owner.clone(), public_key_bytes.clone()),
			Some(CredentialConfig { cred_type: CredentialType::Ecdsa })
		);

		let payload = *b"ECDSA signature should work";
		let signature = ecdsa_sign(0.into(), &public, &payload).unwrap();
		AccountAbstraction::check_abstract_signature(
			&owner,
			public_key_bytes.as_slice(),
			signature.as_slice(),
			payload.as_slice(),
		)
		.expect("ECDSA abstract signature should be valid");
	});
}

#[test]
fn check_abstract_signature_ethereum() {
	new_test_ext().execute_with(|| {
		initialize_to_block(1);
		let owner = acc(1);
		let public: ecdsa::Public = ecdsa_generate(0.into(), None);
		let public_key_bytes: BoundedVec<u8, MaxPublicKeySize> =
			public.encode().try_into().unwrap();
		AccountAbstraction::register_credentials(
			RuntimeOrigin::signed(owner.clone()),
			vec![(
				public_key_bytes.clone(),
				CredentialConfig { cred_type: CredentialType::Ethereum },
			)],
		)
		.expect("Ethereum public key registration should be valid");
		assert_eq!(
			Credentials::<Test>::get(owner.clone(), public_key_bytes.clone()),
			Some(CredentialConfig { cred_type: CredentialType::Ethereum })
		);

		let payload = *b"Ethereum signature should work";
		let mut hash = [0u8; 32];
		hash.copy_from_slice(Keccak256::digest(payload).as_slice());
		let signature = ecdsa_sign_prehashed(0.into(), &public, &hash).unwrap();
		AccountAbstraction::check_abstract_signature(
			&owner,
			public_key_bytes.as_slice(),
			signature.as_slice(),
			payload.as_slice(),
		)
		.expect("Ethereum abstract signature should be valid");
	});
}

#[test]
fn check_abstract_signature_sr25519() {
	new_test_ext().execute_with(|| {
		initialize_to_block(1);
		let owner = acc(1);
		let public: sr25519::Public = sr25519_generate(0.into(), None);
		let public_key_bytes: BoundedVec<u8, MaxPublicKeySize> =
			public.encode().try_into().unwrap();
		AccountAbstraction::register_credentials(
			RuntimeOrigin::signed(owner.clone()),
			vec![(
				public_key_bytes.clone(),
				CredentialConfig { cred_type: CredentialType::Sr25519 },
			)],
		)
		.expect("SR25519 public key registration should be valid");
		assert_eq!(
			Credentials::<Test>::get(owner.clone(), public_key_bytes.clone()),
			Some(CredentialConfig { cred_type: CredentialType::Sr25519 })
		);

		let payload = *b"SR25519 signature should work";
		let signature = sr25519_sign(0.into(), &public, &payload).unwrap();
		AccountAbstraction::check_abstract_signature(
			&owner,
			public_key_bytes.as_slice(),
			signature.as_slice(),
			payload.as_slice(),
		)
		.expect("SR25519 abstract signature should be valid");
	});
}

#[test]
fn check_abstract_signature_ed25519() {
	new_test_ext().execute_with(|| {
		initialize_to_block(1);
		let owner = acc(1);
		let public: ed25519::Public = ed25519_generate(0.into(), None);
		let public_key_bytes: BoundedVec<u8, MaxPublicKeySize> =
			public.encode().try_into().unwrap();
		AccountAbstraction::register_credentials(
			RuntimeOrigin::signed(owner.clone()),
			vec![(
				public_key_bytes.clone(),
				CredentialConfig { cred_type: CredentialType::Ed25519 },
			)],
		)
		.expect("SR25519 public key registration should be valid");
		assert_eq!(
			Credentials::<Test>::get(owner.clone(), public_key_bytes.clone()),
			Some(CredentialConfig { cred_type: CredentialType::Ed25519 })
		);

		let payload = b"ED25519 signature should work";
		let signature = ed25519_sign(0.into(), &public, payload.as_slice()).unwrap();
		AccountAbstraction::check_abstract_signature(
			&owner,
			public_key_bytes.as_slice(),
			signature.as_slice(),
			payload.as_slice(),
		)
		.expect("ED25519 abstract signature should be valid");
	});
}

#[cfg(feature = "bls")]
mod bls {
	use super::*;

	#[test]
	fn check_abstract_signature_bls() {
		new_test_ext().execute_with(|| {
			initialize_to_block(1);
			let owner = acc(1);
			let seed = [5u8; 32];
			let private = blst::min_pk::SecretKey::key_gen(&seed, &[])
				.expect("BLS private key creation from seed should work");
			let public = private.sk_to_pk();
			let public_key_bytes: BoundedVec<u8, MaxPublicKeySize> =
				public.serialize().as_slice().to_vec().try_into().unwrap();
			AccountAbstraction::register_credentials(
				RuntimeOrigin::signed(owner.clone()),
				vec![(
					public_key_bytes.clone(),
					CredentialConfig { cred_type: CredentialType::Bls },
				)],
			)
			.expect("BLS public key registration should be valid");
			assert_eq!(
				Credentials::<Test>::get(owner.clone(), public_key_bytes.clone()),
				Some(CredentialConfig { cred_type: CredentialType::Bls })
			);

			let payload = b"BLS signature should work";
			let signature = private.sign(payload.as_slice(), &[], &[]);
			AccountAbstraction::check_abstract_signature(
				&owner,
				public_key_bytes.as_slice(),
				signature.to_bytes().as_slice(),
				payload.as_slice(),
			)
			.expect("BLS abstract signature should be valid");
		});
	}

	#[test]
	fn register_credential_bls() {
		new_test_ext().execute_with(|| {
			initialize_to_block(1);
			let owner = acc(1);
			let invalid_public_key = blst::min_pk::SecretKey::key_gen(&[1u8; 32], &[]).unwrap();
			let invalid_public_key_bytes: BoundedVec<u8, MaxPublicKeySize> =
				invalid_public_key.serialize().as_slice().to_vec().try_into().unwrap();

			let private = blst::min_pk::SecretKey::key_gen(&[5u8; 32], &[])
				.expect("BLS private key creation from seed should work");
			let public = private.sk_to_pk();
			let public_key_bytes: BoundedVec<u8, MaxPublicKeySize> =
				public.serialize().as_slice().to_vec().try_into().unwrap();
			assert_eq!(Credentials::<Test>::get(owner.clone(), public_key_bytes.clone()), None);
			assert_noop!(
				AccountAbstraction::register_credentials(
					RuntimeOrigin::signed(owner.clone()),
					vec![(
						public_key_bytes.clone(),
						CredentialConfig { cred_type: CredentialType::Sr25519 },
					)],
				),
				Error::<Test>::InvalidPublicKeyLength
			);
			assert_noop!(
				AccountAbstraction::register_credentials(
					RuntimeOrigin::signed(owner.clone()),
					vec![(
						public_key_bytes.clone(),
						CredentialConfig { cred_type: CredentialType::Ed25519 },
					)],
				),
				Error::<Test>::InvalidPublicKeyLength
			);
			assert_noop!(
				AccountAbstraction::register_credentials(
					RuntimeOrigin::signed(owner.clone()),
					vec![(
						invalid_public_key_bytes.clone(),
						CredentialConfig { cred_type: CredentialType::Ecdsa },
					)],
				),
				Error::<Test>::InvalidPublicKeyLength
			);
			AccountAbstraction::register_credentials(
				RuntimeOrigin::signed(owner.clone()),
				vec![(
					public_key_bytes.clone(),
					CredentialConfig { cred_type: CredentialType::Bls },
				)],
			)
			.expect("BLS credential should be successfully registered");
			assert_eq!(
				Credentials::<Test>::get(owner.clone(), public_key_bytes.clone()),
				Some(CredentialConfig { cred_type: CredentialType::Bls })
			);
			System::assert_last_event(RuntimeEvent::AccountAbstraction(
				Event::CredentialRegistered {
					account: owner.clone(),
					public_key: public_key_bytes,
					config: CredentialConfig { cred_type: CredentialType::Bls },
				},
			));
		});
	}
}

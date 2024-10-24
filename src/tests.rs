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
		let acc1 = SmartAccounts::generate_account_from_entropy(&generator).unwrap();
		set.insert(acc1.clone());
		// should generate the same
		set.insert(SmartAccounts::generate_account_from_entropy(&generator).unwrap());
		// second one, same block, increasing nonce.
		System::inc_account_nonce(generator.clone());
		let acc2 = SmartAccounts::generate_account_from_entropy(&generator).unwrap();
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
			SmartAccounts::register_credentials(
				RuntimeOrigin::signed(owner.clone()),
				vec![(
					public_key_bytes.clone(),
					CredentialConfig { cred_type: CredentialType::Sr25519 },
				)],
			),
			Error::<Test>::InvalidPublicKeyLength
		);
		assert_noop!(
			SmartAccounts::register_credentials(
				RuntimeOrigin::signed(owner.clone()),
				vec![(
					public_key_bytes.clone(),
					CredentialConfig { cred_type: CredentialType::Ed25519 },
				)],
			),
			Error::<Test>::InvalidPublicKeyLength
		);
		assert_noop!(
			SmartAccounts::register_credentials(
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
			SmartAccounts::register_credentials(
				RuntimeOrigin::signed(owner.clone()),
				vec![(long_public_key, CredentialConfig { cred_type: CredentialType::Ecdsa },)],
			),
			Error::<Test>::InvalidPublicKeyLength
		);
		let zero_public_key = [0u8; 33].to_vec().try_into().unwrap();
		assert_noop!(
			SmartAccounts::register_credentials(
				RuntimeOrigin::signed(owner.clone()),
				vec![(zero_public_key, CredentialConfig { cred_type: CredentialType::Ecdsa },)],
			),
			Error::<Test>::InvalidPublicKey
		);
		SmartAccounts::register_credentials(
			RuntimeOrigin::signed(owner.clone()),
			vec![(public_key_bytes.clone(), CredentialConfig { cred_type: CredentialType::Ecdsa })],
		)
		.expect("ECDSA credential should be successfully registered");
		assert_eq!(
			Credentials::<Test>::get(owner.clone(), public_key_bytes.clone()),
			Some(CredentialConfig { cred_type: CredentialType::Ecdsa })
		);
		System::assert_last_event(RuntimeEvent::SmartAccounts(Event::CredentialRegistered {
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
			SmartAccounts::register_credentials(
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
			SmartAccounts::register_credentials(
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
			SmartAccounts::register_credentials(
				RuntimeOrigin::signed(owner.clone()),
				vec![(long_public_key, CredentialConfig { cred_type: CredentialType::Sr25519 },)],
			),
			Error::<Test>::InvalidPublicKeyLength
		);
		let zero_public_key = [0u8; 33].to_vec().try_into().unwrap();
		assert_noop!(
			SmartAccounts::register_credentials(
				RuntimeOrigin::signed(owner.clone()),
				vec![(zero_public_key, CredentialConfig { cred_type: CredentialType::Sr25519 },)],
			),
			Error::<Test>::InvalidPublicKeyLength
		);
		SmartAccounts::register_credentials(
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
		System::assert_last_event(RuntimeEvent::SmartAccounts(Event::CredentialRegistered {
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
			SmartAccounts::register_credentials(
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
			SmartAccounts::register_credentials(
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
			SmartAccounts::register_credentials(
				RuntimeOrigin::signed(owner.clone()),
				vec![(long_public_key, CredentialConfig { cred_type: CredentialType::Ed25519 },)]
			),
			Error::<Test>::InvalidPublicKeyLength
		);
		let zero_public_key = [0u8; 33].to_vec().try_into().unwrap();
		assert_noop!(
			SmartAccounts::register_credentials(
				RuntimeOrigin::signed(owner.clone()),
				vec![(zero_public_key, CredentialConfig { cred_type: CredentialType::Ed25519 },)],
			),
			Error::<Test>::InvalidPublicKeyLength
		);
		SmartAccounts::register_credentials(
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
		System::assert_last_event(RuntimeEvent::SmartAccounts(Event::CredentialRegistered {
			account: owner.clone(),
			public_key: public_key_bytes,
			config: CredentialConfig { cred_type: CredentialType::Ed25519 },
		}));
	});
}

#[test]
fn check_smart_signature_ecdsa() {
	new_test_ext().execute_with(|| {
		initialize_to_block(1);
		let owner = acc(1);
		let public: ecdsa::Public = ecdsa_generate(0.into(), None);
		let public_key_bytes: BoundedVec<u8, MaxPublicKeySize> =
			public.encode().try_into().unwrap();
		SmartAccounts::register_credentials(
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
		SmartAccounts::check_smart_signature(
			&owner,
			public_key_bytes.as_slice(),
			signature.as_slice(),
			payload.as_slice(),
		)
		.expect("ECDSA smart signature should be valid");
	});
}

#[test]
fn check_smart_signature_ethereum() {
	new_test_ext().execute_with(|| {
		initialize_to_block(1);
		let owner = acc(1);
		let public: ecdsa::Public = ecdsa_generate(0.into(), None);
		let public_key_bytes: BoundedVec<u8, MaxPublicKeySize> =
			public.encode().try_into().unwrap();
		SmartAccounts::register_credentials(
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
		SmartAccounts::check_smart_signature(
			&owner,
			public_key_bytes.as_slice(),
			signature.as_slice(),
			payload.as_slice(),
		)
		.expect("Ethereum smart signature should be valid");
	});
}

#[test]
fn check_smart_signature_sr25519() {
	new_test_ext().execute_with(|| {
		initialize_to_block(1);
		let owner = acc(1);
		let public: sr25519::Public = sr25519_generate(0.into(), None);
		let public_key_bytes: BoundedVec<u8, MaxPublicKeySize> =
			public.encode().try_into().unwrap();
		SmartAccounts::register_credentials(
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
		SmartAccounts::check_smart_signature(
			&owner,
			public_key_bytes.as_slice(),
			signature.as_slice(),
			payload.as_slice(),
		)
		.expect("SR25519 smart signature should be valid");
	});
}

#[test]
fn check_smart_signature_ed25519() {
	new_test_ext().execute_with(|| {
		initialize_to_block(1);
		let owner = acc(1);
		let public: ed25519::Public = ed25519_generate(0.into(), None);
		let public_key_bytes: BoundedVec<u8, MaxPublicKeySize> =
			public.encode().try_into().unwrap();
		SmartAccounts::register_credentials(
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
		SmartAccounts::check_smart_signature(
			&owner,
			public_key_bytes.as_slice(),
			signature.as_slice(),
			payload.as_slice(),
		)
		.expect("ED25519 smart signature should be valid");
	});
}

#[cfg(feature = "bls")]
mod bls {
	use super::*;

	#[test]
	fn check_smart_signature_bls() {
		new_test_ext().execute_with(|| {
			initialize_to_block(1);
			let owner = acc(1);
			let seed = [5u8; 32];
			let private = blst::min_pk::SecretKey::key_gen(&seed, &[])
				.expect("BLS private key creation from seed should work");
			let public = private.sk_to_pk();
			let public_key_bytes: BoundedVec<u8, MaxPublicKeySize> =
				public.serialize().as_slice().to_vec().try_into().unwrap();
			SmartAccounts::register_credentials(
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
			SmartAccounts::check_smart_signature(
				&owner,
				public_key_bytes.as_slice(),
				signature.to_bytes().as_slice(),
				payload.as_slice(),
			)
			.expect("BLS smart signature should be valid");
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
				SmartAccounts::register_credentials(
					RuntimeOrigin::signed(owner.clone()),
					vec![(
						public_key_bytes.clone(),
						CredentialConfig { cred_type: CredentialType::Sr25519 },
					)],
				),
				Error::<Test>::InvalidPublicKeyLength
			);
			assert_noop!(
				SmartAccounts::register_credentials(
					RuntimeOrigin::signed(owner.clone()),
					vec![(
						public_key_bytes.clone(),
						CredentialConfig { cred_type: CredentialType::Ed25519 },
					)],
				),
				Error::<Test>::InvalidPublicKeyLength
			);
			assert_noop!(
				SmartAccounts::register_credentials(
					RuntimeOrigin::signed(owner.clone()),
					vec![(
						invalid_public_key_bytes.clone(),
						CredentialConfig { cred_type: CredentialType::Ecdsa },
					)],
				),
				Error::<Test>::InvalidPublicKeyLength
			);
			SmartAccounts::register_credentials(
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
			System::assert_last_event(RuntimeEvent::SmartAccounts(Event::CredentialRegistered {
				account: owner.clone(),
				public_key: public_key_bytes,
				config: CredentialConfig { cred_type: CredentialType::Bls },
			}));
		});
	}
}

#[cfg(feature = "rsa")]
mod rsa {
	use super::*;
	use ::rsa::pss::BlindedSigningKey;
	use ::rsa::signature::{RandomizedSigner, SignatureEncoding};
	use ::rsa::{
		pkcs8::{DecodePrivateKey, EncodePublicKey},
		RsaPrivateKey,
	};

	const RSA_PRIVATE: &str = "-----BEGIN PRIVATE KEY-----
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
qcEicKnd2sTeLzLq8qo8avs=
-----END PRIVATE KEY-----
";

	#[test]
	fn check_smart_signature_rsa() {
		new_test_ext().execute_with(|| {
			initialize_to_block(1);
			let owner = acc(1);
			let private = RsaPrivateKey::from_pkcs8_pem(RSA_PRIVATE)
				.expect("RSA private key creation from pem should work");
			let public = private.to_public_key();
			let public_key_bytes: BoundedVec<u8, MaxPublicKeySize> =
				public.to_public_key_der().unwrap().as_bytes().to_vec().try_into().unwrap();
			SmartAccounts::register_credentials(
				RuntimeOrigin::signed(owner.clone()),
				vec![(
					public_key_bytes.clone(),
					CredentialConfig { cred_type: CredentialType::Rsa },
				)],
			)
			.expect("RSA public key registration should be valid");
			assert_eq!(
				Credentials::<Test>::get(owner.clone(), public_key_bytes.clone()),
				Some(CredentialConfig { cred_type: CredentialType::Rsa })
			);

			let mut rng = rand::thread_rng();
			let payload = b"RSA signature should work";
			let signing_key = BlindedSigningKey::<blake2::Blake2s256>::new(private);
			let signature = signing_key.sign_with_rng(&mut rng, payload);
			SmartAccounts::check_smart_signature(
				&owner,
				public_key_bytes.as_slice(),
				signature.to_bytes().as_ref(),
				payload.as_slice(),
			)
			.expect("RSA smart signature should be valid");
		});
	}

	#[test]
	fn register_credential_rsa() {
		new_test_ext().execute_with(|| {
			initialize_to_block(1);
			let owner = acc(1);
			let invalid_private_key =
				RsaPrivateKey::from_p_q(7u128.into(), 11u128.into(), 13u128.into()).unwrap();
			let invalid_public_key_bytes: BoundedVec<u8, MaxPublicKeySize> = invalid_private_key
				.to_public_key()
				.to_public_key_der()
				.unwrap()
				.as_bytes()
				.to_vec()
				.try_into()
				.unwrap();

			let private = RsaPrivateKey::from_pkcs8_pem(RSA_PRIVATE)
				.expect("RSA private key creation from pem should work");
			let public = private.to_public_key();
			let public_key_bytes: BoundedVec<u8, MaxPublicKeySize> =
				public.to_public_key_der().unwrap().as_bytes().to_vec().try_into().unwrap();
			assert_eq!(Credentials::<Test>::get(owner.clone(), public_key_bytes.clone()), None);
			assert_noop!(
				SmartAccounts::register_credentials(
					RuntimeOrigin::signed(owner.clone()),
					vec![(
						public_key_bytes.clone(),
						CredentialConfig { cred_type: CredentialType::Sr25519 },
					)],
				),
				Error::<Test>::InvalidPublicKeyLength
			);
			assert_noop!(
				SmartAccounts::register_credentials(
					RuntimeOrigin::signed(owner.clone()),
					vec![(
						public_key_bytes.clone(),
						CredentialConfig { cred_type: CredentialType::Ed25519 },
					)],
				),
				Error::<Test>::InvalidPublicKeyLength
			);
			assert_noop!(
				SmartAccounts::register_credentials(
					RuntimeOrigin::signed(owner.clone()),
					vec![(
						invalid_public_key_bytes.clone(),
						CredentialConfig { cred_type: CredentialType::Ecdsa },
					)],
				),
				Error::<Test>::InvalidPublicKeyLength
			);
			SmartAccounts::register_credentials(
				RuntimeOrigin::signed(owner.clone()),
				vec![(
					public_key_bytes.clone(),
					CredentialConfig { cred_type: CredentialType::Rsa },
				)],
			)
			.expect("RSA credential should be successfully registered");
			assert_eq!(
				Credentials::<Test>::get(owner.clone(), public_key_bytes.clone()),
				Some(CredentialConfig { cred_type: CredentialType::Rsa })
			);
			System::assert_last_event(RuntimeEvent::SmartAccounts(Event::CredentialRegistered {
				account: owner.clone(),
				public_key: public_key_bytes,
				config: CredentialConfig { cred_type: CredentialType::Rsa },
			}));
		});
	}
}

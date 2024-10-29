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

//! Benchmarking setup for pallet-otro.

use super::*;

use crate::Pallet as Otro;
use frame_benchmarking::{v2::*, whitelisted_caller};

fn assert_has_event<T: Config>(generic_event: <T as Config>::RuntimeEvent) {
	frame_system::Pallet::<T>::assert_has_event(generic_event.into());
}

#[benchmarks]
mod benchmarks {
	use super::*;
	use frame_support::dispatch::RawOrigin;
	use frame_support::BoundedVec;
	use parity_scale_codec::Encode;
	use sp_core::ecdsa;
	use sp_io::crypto::ecdsa_generate;
	use sp_std::vec::Vec;

	#[benchmark]
	fn generate_account(c: Linear<1, 100>) {
		let caller: T::AccountId = whitelisted_caller();

		let mut credentials = Vec::with_capacity(c as usize);
		for _ in 0..c {
			let public: ecdsa::Public = ecdsa_generate(0.into(), None);
			let public_key_bytes: BoundedVec<u8, T::MaxPublicKeySize> =
				public.encode().try_into().unwrap();
			let credential =
				(public_key_bytes, CredentialConfig { cred_type: CredentialType::Ecdsa });
			credentials.push(credential);
		}

		#[extrinsic_call]
		_(RawOrigin::Signed(caller.clone()), credentials.clone());

		let generated_account = Otro::<T>::generate_account_from_entropy(&caller).unwrap();

		assert_has_event::<T>(
			Event::<T>::SmartAccountGenerated {
				generator: caller,
				account: generated_account.clone(),
			}
			.into(),
		);
		for credential in credentials {
			assert_has_event::<T>(
				Event::<T>::CredentialRegistered {
					account: generated_account.clone(),
					public_key: credential.0.clone(),
					config: credential.1.clone(),
				}
				.into(),
			);
			assert_eq!(
				Credentials::<T>::get(generated_account.clone(), credential.0),
				Some(credential.1)
			);
		}
	}

	#[benchmark]
	fn register_credentials(c: Linear<1, 100>) {
		let caller: T::AccountId = whitelisted_caller();

		let mut credentials = Vec::with_capacity(c as usize);
		for _ in 0..c {
			let public: ecdsa::Public = ecdsa_generate(0.into(), None);
			let public_key_bytes: BoundedVec<u8, T::MaxPublicKeySize> =
				public.encode().try_into().unwrap();
			let credential =
				(public_key_bytes, CredentialConfig { cred_type: CredentialType::Ecdsa });
			credentials.push(credential);
		}

		#[extrinsic_call]
		_(RawOrigin::Signed(caller.clone()), credentials.clone());

		for credential in credentials {
			assert_has_event::<T>(
				Event::<T>::CredentialRegistered {
					account: caller.clone(),
					public_key: credential.0.clone(),
					config: credential.1.clone(),
				}
				.into(),
			);
			assert_eq!(Credentials::<T>::get(caller.clone(), credential.0), Some(credential.1));
		}
	}

	#[benchmark]
	fn unregister_credential() {
		let caller: T::AccountId = whitelisted_caller();

		let mut credentials = Vec::new();
		let public: ecdsa::Public = ecdsa_generate(0.into(), None);
		let public_key_bytes: BoundedVec<u8, T::MaxPublicKeySize> =
			public.encode().try_into().unwrap();
		let credential =
			(public_key_bytes.clone(), CredentialConfig { cred_type: CredentialType::Ecdsa });
		credentials.push(credential);
		Otro::<T>::register_credentials(
			RawOrigin::Signed(caller.clone()).into(),
			credentials.clone(),
		)
		.unwrap();

		#[extrinsic_call]
		_(RawOrigin::Signed(caller.clone()), public_key_bytes.clone());

		assert_has_event::<T>(
			Event::<T>::CredentialUnregistered {
				account: caller.clone(),
				public_key: public_key_bytes.clone(),
			}
			.into(),
		);
		assert_eq!(Credentials::<T>::get(caller.clone(), public_key_bytes), None);
	}

	impl_benchmark_test_suite!(Otro, crate::mock::new_test_ext(), crate::mock::Test);
}

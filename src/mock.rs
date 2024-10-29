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

use frame_support::{derive_impl, parameter_types};
use sp_io::TestExternalities;
use sp_keystore::testing::MemoryKeystore;
use sp_keystore::KeystoreExt;
use sp_runtime::traits::IdentifyAccount;
use sp_runtime::traits::IdentityLookup;
use sp_runtime::{traits::Verify, BuildStorage, MultiSignature};
use sp_std::sync::Arc;

use crate as pallet_otro;

use super::*;

pub type Signature = MultiSignature;
pub type AccountPublic = <Signature as Verify>::Signer;
pub type AccountId = <AccountPublic as IdentifyAccount>::AccountId;
type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
	pub enum Test
	{
		System: frame_system,
		Otro: pallet_otro,
	}
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
	type AccountId = AccountId;
	type Lookup = IdentityLookup<Self::AccountId>;
	type Block = Block;
}

parameter_types! {
	pub const SignaturePrelude: [u8; 8] = *b"sigprlud";
	pub const MaxPublicKeySize: u32 = 1024;
}

impl Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type SignaturePrelude = SignaturePrelude;
	type MaxPublicKeySize = MaxPublicKeySize;
	type WeightInfo = ();
}

pub fn new_test_ext() -> sp_io::TestExternalities {
	let t = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();
	let mut ext = TestExternalities::new(t);
	let keystore = MemoryKeystore::new();
	ext.register_extension(KeystoreExt(Arc::new(keystore)));

	ext.execute_with(|| initialize_to_block(1));
	ext
}

pub fn initialize_to_block(n: u64) {
	for i in System::block_number() + 1..=n {
		System::set_block_number(i);
		<AllPalletsWithSystem as frame_support::traits::OnInitialize<u64>>::on_initialize(i);
	}
}

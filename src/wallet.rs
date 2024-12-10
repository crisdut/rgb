// Wallet Library for RGB smart contracts
//
// SPDX-License-Identifier: Apache-2.0
//
// Designed in 2019-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
// Written in 2024-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association, Switzerland.
// Copyright (C) 2024-2025 LNP/BP Laboratories,
//                         Institute for Distributed and Cognitive Systems (InDCS), Switzerland.
// Copyright (C) 2025 RGB Consortium, Switzerland.
// Copyright (C) 2019-2025 Dr Maxim Orlovsky.
// All rights under the above copyrights are reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
// in compliance with the License. You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied. See the License for the specific language governing permissions and limitations under
// the License.

use bpstd::{Network, XpubDerivable};
use bpwallet::{Layer2Empty, NoLayer2, Wallet, WalletCache, WalletData, WalletDescr};
use nonasync::persistence::{PersistenceError, PersistenceProvider};
use rgb::popls::bp::{OpretProvider, TapretProvider, WalletProvider};

use crate::descriptor::{Opret, Tapret};

// TODO: Use layer 2 supporting Lightning
#[derive(Wrapper, WrapperMut, From)]
#[wrapper(Deref)]
#[wrapper_mut(DerefMut)]
pub struct OpretWallet(Wallet<XpubDerivable, Opret<XpubDerivable>, NoLayer2>);

impl WalletProvider for OpretWallet {}
impl OpretProvider for OpretWallet {}

impl OpretWallet {
    pub fn create<P>(
        provider: P,
        descr: Opret<XpubDerivable>,
        network: Network,
        autosave: bool,
    ) -> Result<Self, PersistenceError>
    where
        P: Clone
            + PersistenceProvider<WalletDescr<XpubDerivable, Opret<XpubDerivable>, Layer2Empty>>
            + PersistenceProvider<WalletData<Layer2Empty>>
            + PersistenceProvider<WalletCache<Layer2Empty>>
            + PersistenceProvider<NoLayer2>
            + 'static,
    {
        let mut wallet = Wallet::new_layer1(descr, network);
        wallet.make_persistent(provider, autosave)?;
        Ok(Self(wallet))
    }

    pub fn load<P>(provider: P, autosave: bool) -> Result<Self, PersistenceError>
    where P: Clone
            + PersistenceProvider<WalletDescr<XpubDerivable, Opret<XpubDerivable>, Layer2Empty>>
            + PersistenceProvider<WalletData<Layer2Empty>>
            + PersistenceProvider<WalletCache<Layer2Empty>>
            + PersistenceProvider<NoLayer2>
            + 'static {
        Wallet::load(provider, autosave).map(OpretWallet)
    }
}

#[derive(Wrapper, WrapperMut, From)]
#[wrapper(Deref)]
#[wrapper_mut(DerefMut)]
pub struct TapretWallet(Wallet<XpubDerivable, Tapret<XpubDerivable>, NoLayer2>);

impl WalletProvider for TapretWallet {}
impl TapretProvider for TapretWallet {}

impl TapretWallet {
    pub fn create<P>(
        provider: P,
        descr: Tapret<XpubDerivable>,
        network: Network,
        autosave: bool,
    ) -> Result<Self, PersistenceError>
    where
        P: Clone
            + PersistenceProvider<WalletDescr<XpubDerivable, Tapret<XpubDerivable>, Layer2Empty>>
            + PersistenceProvider<WalletData<Layer2Empty>>
            + PersistenceProvider<WalletCache<Layer2Empty>>
            + PersistenceProvider<NoLayer2>
            + 'static,
    {
        let mut wallet = Wallet::new_layer1(descr, network);
        wallet.make_persistent(provider, autosave)?;
        Ok(Self(wallet))
    }

    pub fn load<P>(provider: P, autosave: bool) -> Result<Self, PersistenceError>
    where P: Clone
            + PersistenceProvider<WalletDescr<XpubDerivable, Tapret<XpubDerivable>, Layer2Empty>>
            + PersistenceProvider<WalletData<Layer2Empty>>
            + PersistenceProvider<WalletCache<Layer2Empty>>
            + PersistenceProvider<NoLayer2>
            + 'static {
        Wallet::load(provider, autosave).map(TapretWallet)
    }
}

#[cfg(feature = "fs")]
pub mod file {
    use rgb::popls::bp::file::DirBarrow;

    use super::*;

    #[derive(Wrapper, WrapperMut, From)]
    #[wrapper(Deref)]
    #[wrapper_mut(DerefMut)]
    pub struct DirRuntime(DirBarrow<OpretWallet, TapretWallet>);
}

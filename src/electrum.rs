use std::collections::{BTreeMap, BTreeSet};

use amplify::{Wrapper, ByteArray};
use bitcoin::hashes::Hash;
use bitcoin::{Script, ScriptBuf};
use bp::{LockTime, SeqNo, Tx, TxIn, TxOut, TxVer, VarIntArray, Witness};
use electrum_client::{ElectrumApi, Error};
use rgbstd::contract::WitnessOrd;
use rgbstd::resolvers::ResolveHeight;
use rgbstd::validation::{ResolveTx, TxResolverError};

use super::*;
use crate::descriptor::DeriveInfo;
use crate::wallet::Utxo;

#[derive(Wrapper, WrapperMut, From)]
#[wrapper(Deref)]
#[wrapper_mut(DerefMut)]
pub struct BlockchainResolver(electrum_client::Client);

impl BlockchainResolver {
    pub fn with(url: &str) -> Result<Self, electrum_client::Error> {
        electrum_client::Client::new(url).map(Self)
    }
}

impl Resolver for BlockchainResolver {
    fn resolve_utxo<'s>(
        &mut self,
        scripts: BTreeMap<DeriveInfo, ScriptBuf>,
    ) -> Result<BTreeSet<Utxo>, String> {
        Ok(self
            .batch_script_list_unspent(scripts.values().map(ScriptBuf::as_script))
            .map_err(|err| err.to_string())?
            .into_iter()
            .zip(scripts.into_keys())
            .flat_map(|(list, derivation)| {
                list.into_iter()
                    .map(move |res| Utxo::with(derivation.clone(), res))
            })
            .collect())
    }
}

impl ResolveTx for BlockchainResolver {
    fn resolve_tx(&self, txid: Txid) -> Result<Tx, TxResolverError> {
        let tx = self
            .0
            .transaction_get(&bitcoin::Txid::from_byte_array(txid.to_byte_array()))
            .map_err(|err| match err {
                Error::Message(_) | Error::Protocol(_) => TxResolverError::Unknown(txid),
                err => TxResolverError::Other(txid, err.to_string()),
            })?;
        Ok(Tx {
            version: TxVer::from_consensus_i32(tx.version),
            inputs: VarIntArray::try_from_iter(tx.input.into_iter().map(|txin| TxIn {
                prev_output: Outpoint::new(
                    txin.previous_output.txid.to_byte_array().into(),
                    txin.previous_output.vout,
                ),
                sig_script: txin.script_sig.to_bytes().into(),
                sequence: SeqNo::from_consensus_u32(txin.sequence.to_consensus_u32()),
                witness: Witness::from_consensus_stack(txin.witness.to_vec()),
            }))
            .expect("consensus-invalid transaction"),
            outputs: VarIntArray::try_from_iter(tx.output.into_iter().map(|txout| TxOut {
                value: txout.value.into(),
                script_pubkey: txout.script_pubkey.to_bytes().into(),
            }))
            .expect("consensus-invalid transaction"),
            lock_time: LockTime::from_consensus_u32(tx.lock_time.to_consensus_u32()),
        })
    }
}

impl ResolveHeight for BlockchainResolver {
    type Error = TxResolverError;
    fn resolve_height(&mut self, txid: Txid) -> Result<WitnessOrd, Self::Error> {
        let tx = match self
            .0
            .transaction_get(&bitcoin::Txid::from_byte_array(txid.to_byte_array()))
        {
            Ok(tx) => tx,
            Err(Error::Message(_) | Error::Protocol(_)) => return Ok(WitnessOrd::OffChain),
            Err(err) => return Err(TxResolverError::Other(txid, err.to_string())),
        };

        let scripts: Vec<&Script> = tx
            .output
            .iter()
            .map(|out| out.script_pubkey.as_script())
            .collect();

        let mut hists = vec![];
        self.0
            .batch_script_get_history(scripts)
            .map_err(|err| match err {
                Error::Message(_) | Error::Protocol(_) => TxResolverError::Unknown(txid),
                err => TxResolverError::Other(txid, err.to_string()),
            })?
            .into_iter()
            .for_each(|h| hists.extend(h));
        let transactions: BTreeMap<bitcoin::Txid, u32> = hists
            .into_iter()
            .map(|h| (h.tx_hash, if h.height > 0 { h.height as u32 } else { 0 }))
            .collect();

        let min_height = transactions
            .into_values()
            .min()
            .map(WitnessOrd::with_mempool_or_height)
            .unwrap_or(WitnessOrd::OffChain);

        Ok(min_height)
    }
}

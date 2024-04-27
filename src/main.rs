use elements::bitcoin::{taproot, TapSighashType};
use elements::encode::deserialize;
use elements::secp256k1_zkp::schnorr::Signature;
use std::str::FromStr;

use elements::hashes::{sha256, Hash};
use elements::hex::FromHex;
use elements::pset::PartiallySignedTransaction as Pset;
use elements::secp256k1_zkp::Message;
use elements::sighash::Prevouts;

use elements::{
    confidential,
    schnorr::UntweakedPublicKey,
    secp256k1_zkp::{Parity, Secp256k1},
    sighash::SighashCache,
    Address, AddressParams, AssetId, SchnorrSighashType, TxOut, TxOutWitness,
};
use elements::{pset, BlockHash, OutPoint, Txid};
use leptos::*;
use log::{error, info};
use nostr::{key::PublicKey as NostrPubKey, nips::nip19::FromBech32};
use serde::Deserialize;
use serde_json::from_str;

use wasm_bindgen::prelude::*;

#[derive(Deserialize, Debug)]
struct Utxo {
    txid: String,
    vout: u32,
    status: Status,
    valuecommitment: String,
    assetcommitment: String,
    noncecommitment: String,
}

#[derive(Deserialize, Debug)]
struct Status {
    confirmed: Option<bool>,
    block_height: u64,
    block_hash: String,
    block_time: u64,
}

fn main() {
    _ = console_log::init_with_level(log::Level::Debug);
    console_error_panic_hook::set_once();

    //let npub = "npub1xqrsvnyp9szl0gqww7de27yy3ag3sq64zhr8lq64dwr24le2x54q99xywr";
    let npub = "npub19jkms4jcz4eepux64tqzfn7dscawfglvxynz8fk74t6l8a2n4j8sd8k06m";

    info!("Nostr npub: {}", npub);

    match NostrPubKey::from_bech32(npub) {
        Ok(pubkey_xor) => {
            let pubkey_string: String = pubkey_xor.to_string();
            // info!("Public Key Hex {}", pubkey_string);
            let internal_key = UntweakedPublicKey::from_str(&pubkey_string).unwrap();
            let secp = Secp256k1::verification_only();

            let unblinded_p2tr_address =
                Address::p2tr(&secp, internal_key, None, None, &AddressParams::LIQUID);

            let blinder = pubkey_xor.public_key(Parity::Odd);

            let blinded_p2tr_address = Address::p2tr(
                &secp,
                internal_key,
                None,
                Some(blinder),
                &AddressParams::LIQUID,
            );

            let npub_text = format!("Nostr public key: {}", npub);
            let unblinded_text = format!(
                "Unblinded liquid taproot address: {}",
                unblinded_p2tr_address
            );
            let blinded_text = format!("Blinded liquid taproot address: {}", blinded_p2tr_address);

            mount_to_body(
                || view! {<p>{ npub_text }</p><p>{ unblinded_text }</p><p>{ blinded_text }</p>},
            );

            spawn_local(async move {
                let res = reqwasm::http::Request::get(&format!(
                    "https://liquid.network/api/address/{}/utxo",
                    unblinded_p2tr_address
                ))
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap();

                let utxos: Vec<Utxo> = from_str(&res).expect("Failed to deserialize JSON");

                if utxos.is_empty() {
                    info!("No UTXOs found for address: {}", unblinded_p2tr_address);
                    return;
                }

                let utxo = &utxos[0];

                info!("UTXO: {:?}", utxo);

                let mut psbt = Pset::new_v2();

                let txout = TxOut {
                    asset: deserialize::<confidential::Asset>(
                        &Vec::<u8>::from_hex(&utxo.assetcommitment).unwrap(),
                    )
                    .unwrap(),
                    value: deserialize::<confidential::Value>(
                        &Vec::<u8>::from_hex(&utxo.valuecommitment).unwrap(),
                    )
                    .unwrap(),
                    nonce: deserialize::<confidential::Nonce>(
                        &Vec::<u8>::from_hex(&utxo.noncecommitment).unwrap(),
                    )
                    .unwrap(),
                    script_pubkey: blinded_p2tr_address.clone().script_pubkey(),
                    witness: TxOutWitness::default(),
                };

                //input
                let mut inp = pset::Input::from_prevout(OutPoint::new(
                    Txid::from_str(&utxo.txid).unwrap(),
                    utxo.vout,
                ));
                inp.witness_utxo = Some(txout.clone());
                psbt.add_input(inp);

                //outputs

                let dest_address = blinded_p2tr_address.clone();
                let dest_btc_amt = 1_000;
                let dest_btc_txout = TxOut {
                    asset: confidential::Asset::Explicit(AssetId::LIQUID_BTC),
                    value: confidential::Value::Explicit(dest_btc_amt),
                    nonce: confidential::Nonce::Confidential(blinder),
                    script_pubkey: dest_address.script_pubkey(),
                    witness: TxOutWitness::default(),
                };

                let psbt_transaction = psbt.extract_tx().unwrap();

                let mut sighash_cache = SighashCache::new(&psbt_transaction);

                info!("Sighash_cache: {:?}", sighash_cache);

                let blockhash = BlockHash::from_str(&utxo.status.block_hash).unwrap();

                let sighash_type = SchnorrSighashType::All;

                let sighash = sighash_cache
                    .taproot_key_spend_signature_hash(
                        0,
                        &Prevouts::All(&[dest_btc_txout]),
                        sighash_type,
                        blockhash,
                    )
                    .unwrap();

                info!("psbt: {:?}", psbt);

                let hash_bytes: [u8; 32] = sighash.to_raw_hash().to_byte_array();

                let signed_hash = sign_hash(&hash_bytes).await;

                info!("Signed hash: {}", signed_hash);

                let sig: Signature = Signature::from_str(&signed_hash).unwrap();

                let final_signature = taproot::Signature {
                    sig,
                    hash_ty: TapSighashType::All,
                };

                info!("Final Signature: {:?}", final_signature);
            });
        }
        Err(e) => {
            error!("Failed to parse Nostr Public Key: {}", e);
        }
    };
}

#[wasm_bindgen(inline_js = r#"
export async function sign_schnorr(sigHash) {
    console.log("Sign Schnorr called with hash: ", sigHash);
    return await window.nostr.signSchnorr(sigHash);
}
"#)]
extern "C" {
    async fn sign_schnorr(sig_hash: &JsValue) -> JsValue;
}

#[wasm_bindgen]
pub async fn sign_hash(sig_hash: &[u8]) -> String {
    let msg = Message::from_hashed_data::<sha256::Hash>(sig_hash);
    let msg_jsvalue = JsValue::from_str(&msg.to_string());
    let result = sign_schnorr(&msg_jsvalue).await;
    result.as_string().unwrap()
}

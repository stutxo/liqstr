use elements::{bech32::Fe32, Address, AddressParams, Script};
use leptos::{mount_to_body, view};
use log::{error, info};
use nostr::{key::PublicKey as NostrPubKey, util::hex};

fn main() {
    _ = console_log::init_with_level(log::Level::Debug);
    console_error_panic_hook::set_once();

    let npub = "npub1xqrsvnyp9szl0gqww7de27yy3ag3sq64zhr8lq64dwr24le2x54q99xywr";

    info!("Nostr npub: {}", npub);

    let nostr_pub_key = NostrPubKey::parse(npub);

    match nostr_pub_key {
        Ok(pubkey) => {
            let pubkey_to_hex = pubkey.to_string();

            info!("Nostr Public Key (as hex): {}", pubkey_to_hex);

            match hex::decode(&pubkey_to_hex) {
                Ok(pubkey_bytes) => {
                    let witness_version = Fe32::from(elements::bitcoin::WitnessVersion::V0);

                    info!("witness_version: {}", witness_version);

                    let script_pubkey = Script::new_witness_program(witness_version, &pubkey_bytes);

                    info!("script_pubkey: {}", script_pubkey);

                    let address = Address::p2wsh(&script_pubkey, None, &AddressParams::LIQUID);

                    info!("liquid address: {}", address);

                    let display_text = format!("Liquid Address: {}", address);
                    mount_to_body(|| view! { <p>{ display_text }</p> });
                }
                Err(e) => {
                    error!("Failed to decode hex: {}", e);
                }
            }
        }
        Err(e) => {
            error!("Failed to parse Nostr Public Key: {}", e);
        }
    };
}

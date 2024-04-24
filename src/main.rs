use std::str::FromStr;

use elements::{schnorr::UntweakedPublicKey, secp256k1_zkp::Secp256k1, Address, AddressParams};
use leptos::{mount_to_body, view};
use log::{error, info};
use nostr::{key::PublicKey as NostrPubKey, nips::nip19::FromBech32};

fn main() {
    _ = console_log::init_with_level(log::Level::Debug);
    console_error_panic_hook::set_once();

    let npub = "npub1xqrsvnyp9szl0gqww7de27yy3ag3sq64zhr8lq64dwr24le2x54q99xywr";

    info!("Nostr npub: {}", npub);

    let nostr_pub_key = NostrPubKey::from_bech32(npub);

    match nostr_pub_key {
        Ok(pubkey_hex) => {
            info!("Public key hex: {}", pubkey_hex);
            let pubkey_string: String = pubkey_hex.to_string();

            let internal_key = UntweakedPublicKey::from_str(&pubkey_string).unwrap();
            let secp = Secp256k1::verification_only();

            let p2tr_address =
                Address::p2tr(&secp, internal_key, None, None, &AddressParams::LIQUID);

            let display_text = format!("liquid taproot address: {}", p2tr_address);

            info!("{}", display_text);

            mount_to_body(|| view! { <p>{ display_text }</p> });
        }
        Err(e) => {
            error!("Failed to parse Nostr Public Key: {}", e);
        }
    };
}

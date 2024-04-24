use std::str::FromStr;

use elements::{
    schnorr::UntweakedPublicKey,
    secp256k1_zkp::{Parity, Secp256k1},
    Address, AddressParams,
};
use leptos::{mount_to_body, view};
use log::{error, info};
use nostr::{key::PublicKey as NostrPubKey, nips::nip19::FromBech32};

fn main() {
    _ = console_log::init_with_level(log::Level::Debug);
    console_error_panic_hook::set_once();

    let npub = "npub1xqrsvnyp9szl0gqww7de27yy3ag3sq64zhr8lq64dwr24le2x54q99xywr";

    info!("Nostr npub: {}", npub);

    match NostrPubKey::from_bech32(npub) {
        Ok(pubkey_xor) => {
            let pubkey_string: String = pubkey_xor.to_string();
            info!("Public Key Xor {}", pubkey_xor);
            info!("Public Key Hex {}", pubkey_string);
            let internal_key = UntweakedPublicKey::from_str(&pubkey_string).unwrap();
            let secp = Secp256k1::verification_only();

            let unblinded_p2tr_address =
                Address::p2tr(&secp, internal_key, None, None, &AddressParams::LIQUID);

            let blinder = pubkey_xor.public_key(Parity::Odd);
            info!("Blinder Public Key: {}", blinder.to_string());

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
        }
        Err(e) => {
            error!("Failed to parse Nostr Public Key: {}", e);
        }
    };
}

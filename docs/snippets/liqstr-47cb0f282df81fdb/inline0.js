
export async function sign_schnorr(sigHash) {
    console.log("Sign Schnorr called with hash: ", sigHash);
    return await window.nostr.signSchnorr(sigHash);
}

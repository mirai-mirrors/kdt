// -- imports --
use crate::core::*;

// -- tests --
#[test]
fn kyber_with_correct_privkey() {
    let secret_message = String::from("This is a test message");

    let (pubkey, privkey) = {
        let keyset = OwnedKeySet::generate("Test Key".into());

        (
            keyset.pubkey_pair.to_string(),
            keyset.privkey_pair.crypto_key,
        )
    };
    let encrypted = KdtCryptoHandler::encrypt_text(secret_message.clone(), pubkey).unwrap();
    let decrypted = KdtCryptoHandler::decrypt_msg(encrypted, privkey);

    assert_eq!(decrypted, secret_message);
}

#[test]
#[should_panic]
fn kyber_with_incorrect_privkey() {
    let secret_message = String::from("This is a test message");
    let (pubkey, privkey) = {
        let keyset_1 = OwnedKeySet::generate("Test Key".into());
        let keyset_2 = OwnedKeySet::generate("Test Key".into());

        (
            keyset_1.pubkey_pair.to_string(),
            keyset_2.privkey_pair.crypto_key,
        )
    };
    let encrypted = KdtCryptoHandler::encrypt_text(secret_message, pubkey).unwrap();
    // should panic here because the key is wrong
    KdtCryptoHandler::decrypt_msg(encrypted, privkey);
}

#[test]
fn dilithium_with_correct_pubkey() {
    let text = String::from("This is a test message");
    let (pubkey, privkey) = {
        let keyset = OwnedKeySet::generate("Test Key".into());

        (
            keyset.pubkey_pair.signage_key,
            keyset.privkey_pair.signage_key,
        )
    };

    let signed_text = KdtSignageHandler::sign_text(text, privkey, pubkey.clone());
    let signature_is_valid = {
        let parts: Vec<String> = signed_text
            .chars()
            .skip(35)
            .take(signed_text.len() - 35 - 27)
            .collect::<String>()
            .split("-----BEGIN KDT SIGNATURE-----")
            .map(|x| x.trim())
            .map(String::from)
            .collect();
        let derived_text = parts.first().unwrap().trim().to_owned();
        let derived_signature = parts.last().unwrap().replace("\n", "");
        KdtSignageHandler::verify(derived_text, derived_signature, pubkey)
    };

    assert!(signature_is_valid);
}

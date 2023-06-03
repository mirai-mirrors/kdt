// -- imports --
use crate::core::*;
use pqc_dilithium::Keypair;

// -- tests --
#[test]
fn kyber_with_correct_privkey() {
    let secret_message = String::from("This is a test message");

    let (pubkey, privkey) = {
        let keyset = OwnedKeySet::generate("Test Key".into());

        (
            keyset.pubkey_pair.crypto_key,
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
            keyset_1.pubkey_pair.crypto_key,
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
    let keypair = {
        let keyset = OwnedKeySet::generate("Test Key".into());

        Keypair::restore_from_keys(
            keyset.pubkey_pair.signage_key,
            keyset.privkey_pair.signage_key,
        )
    };

    let signed_text = KdtSignageHandler::sign_text(text, keypair);
    let msg = KdtSignedMessage::from_str(signed_text);
    let signature_validity = KdtSignageHandler::verify(msg, keypair.public.to_vec());
    assert!(signature_validity);
}

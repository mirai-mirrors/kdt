// -- imports --
mod arguments;
mod core;
use crate::arguments::*;
use crate::core::*;
use clap::Parser;

fn main() {
    let args = Args::parse();
    let logger = Logger::new(true);
    if let Err(e) = args.fail_if_invalid() {
        logger.fatal(e);
    }
    if args.get_num_called() == 0 {
        logger.fatal(
            "You didn't pass any arguments! Run `kdt -h` for a list of possible flags and args.",
        );
    }
    let mut kdt = match CoreKdtHandler::new() {
        Ok(k) => k,
        Err(e) => logger.fatal(e),
    };

    // ~ arg handling ~
    // Note to self - figure out how to make this
    // part of the code less ugly.
    {
        // options
        // `--export-pubkey`
        if let Some(pubkey_id) = args.export_pubkey {
            logger.success(format!("Public key for key id {}:", pubkey_id));
            println!(
                "{}",
                kdt.ownedkey_db.get_by_id(pubkey_id).pubkey_pair.to_string()
            );
        }
        // `--del-pubkey`
        if let Some(pubkey_id) = args.del_pubkey {
            logger.info(format!("Removing public key with id {}...", pubkey_id));
            kdt.del_pubkey(pubkey_id);
            logger.success("Successfully removed the public key!");
        }
        // `--del-keyset`
        if let Some(privkey_id) = args.del_keyset {
            logger.info(format!(
                "Removing owned key set with private key id {}...",
                privkey_id
            ));
            kdt.del_ownedkey(privkey_id);
            logger.success("Succesfully removed the owned key set!");
        }
        // `-e | --encrypt`
        if let Some(id) = args.encrypt {
            logger.info("Type your message below (CTRL-D to finish):");
            let message = logger.input();
            logger.info("Encrypted message:");
            println!("{}", kdt.encrypt(id, message));
        }
        // `-d | --decrypt`
        if let Some(privkey_id) = args.decrypt {
            logger.info("Input the encrypted message below (CTRL-D to finish):");
            let message = logger.input();
            logger.info("Decrypted message:");
            println!("{}", kdt.decrypt(privkey_id, message));
        }
        // `-s | --sign`
        if let Some(privkey_id) = args.sign {
            logger.info("Input the message to sign below (CTRL-D to finish):");
            let message = logger.input();
            logger.info("Signed message:");
            println!("{}", kdt.sign(privkey_id, message));
        }
        // `-v | --verify`
        if let Some(pubkey_id) = args.verify {
            logger.info("Input the signed message below (CTRL-D to finish):");
            let message = logger.input();
            let is_valid = kdt.verify(pubkey_id, message);
            match is_valid {
                Some(v) => {
                    if v {
                        logger.success("The provided message is valid!");
                    } else {
                        logger.warn("The given message is not valid!");
                    }
                }
                None => logger.fatal("There was an error parsing your input!"),
            }
        }

        // flags
        // `-l | --list-key-pairs`
        if args.list_key_pairs {
            if kdt.ownedkey_db.is_empty() {
                logger.fatal("You don't have any private keys!");
            }
            logger.info("Keys in your owned key database:");
            for key in &kdt.ownedkey_db.keys {
                println!(
                    "ID: {}\nOwner: {}",
                    key.privkey_pair.id,
                    String::from_utf8_lossy(&Base64::decode_string(key.clone().privkey_pair.owner))
                );
            }
        }
        // `-g | --gen-key`
        if args.gen_key {
            logger.info("Type your name below. Note that this will be visible to everyone who imports your public key.");
            let name = logger.input();
            logger.info("Generating owned key set...");
            let privkey_id = kdt.gen_key(if name.is_empty() {
                String::from("No name was provided by the key owner!")
            } else {
                name
            });
            logger.success(format!(
                "Successfully created owned key with private id {}!",
                privkey_id
            ))
        }
        // `-i | --import`
        if args.import {
            logger.info("Input the public KDT key below (CTRL-D to finish):");
            let pubkey = logger.input();
            let maybe_pubkey_id = kdt.register_pubkey(pubkey);
            match maybe_pubkey_id {
                Ok(id) => logger.success(format!(
                    "Successfully imported KDT public key with id `{}`!",
                    id
                )),
                Err(e) => {
                    logger.fatal(e);
                }
            }
        }
        // `--list-keys`
        if args.list_keys {
            if kdt.pubkey_db.is_empty() {
                logger.fatal("You don't have any public keys!");
            }
            logger.info("Keys in your public key database:");
            for key in &kdt.pubkey_db.keys {
                println!(
                    "ID: {}\nOwner: {}",
                    key.id,
                    String::from_utf8_lossy(&Base64::decode_string(key.clone().owner))
                );
            }
        }
    }

    // Dump the datasets loaded in memory back to
    // their respective files. If this fails, write
    // a fatal log then panic.
    if let Err(e) = kdt.dump_db() {
        logger.fatal(e);
    }
}

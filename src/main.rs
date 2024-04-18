#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::UniformRand;
use clap::{value_parser, Arg, Command};
use mina_curves::pasta::Pallas as CurvePoint;
use o1_utils::FieldHelpers;

type ScalarField = <CurvePoint as AffineCurve>::ScalarField;
type BaseField = <CurvePoint as AffineCurve>::BaseField;

fn max_hex_len() -> usize {
    2 * ScalarField::size_in_bytes()
}

fn max_b58_len() -> usize {
    // max length of 32bytes encoded as base58
    (ScalarField::size_in_bytes() as f32 * 8.0 / 58f32.log2()).ceil() as usize
}

fn compute_pubkey(seckey: ScalarField) -> CurvePoint {
    CurvePoint::prime_subgroup_generator()
        .mul(seckey)
        .into_affine()
}

fn create_keypair() -> (ScalarField, CurvePoint) {
    let seckey = ScalarField::rand(&mut rand::rngs::OsRng);
    let pubkey: CurvePoint = compute_pubkey(seckey);
    (seckey, pubkey)
}

fn create_shared_secret(a_seckey: ScalarField, b_pubkey: CurvePoint) -> ScalarField {
    let curve_point = b_pubkey.mul(a_seckey).into_affine();
    ScalarField::from_bytes(&curve_point.x.to_bytes()).unwrap() // change of field (I promise it's OK)
}

enum KeyFormat {
    Hex,
    B58,
    Bip39,
}

fn format_secret(shared_secret: ScalarField, out: &str, len: usize, suffix: &str) -> String {
    assert!(suffix.len() <= 8);

    let max_len = if out == "b58" {
        max_b58_len()
    } else {
        max_hex_len()
    };
    if len + suffix.len() > max_len {
        panic!("Maximum length possible is {}", max_len - suffix.len());
    }

    match out {
        "b58" => bs58::encode(&shared_secret.to_bytes()).into_string()[..len].to_string() + suffix,
        "hex" => hex::encode(shared_secret.to_bytes())[..len].to_string() + suffix,
        "bip39" => bip39::Mnemonic::from_entropy(&shared_secret.to_bytes())
            .unwrap()
            .to_string(),
        _ => panic!("invalid output type"),
    }
}

fn main() {
    let args = Command::new("dhke")
        .version("0.1.0")
        .author("Joseph Spadavecchia <joseph@redtrie.com>")
        .about("Diffie–Hellman key exchange")
        .arg(
            Arg::new("mode")
                .short('m')
                .long("mode")
                .takes_value(true)
                .required(true)
                .help("Mode of operation")
                .possible_values(["keypair", "shared-secret"]),
        )
        .arg(
            Arg::new("sec")
                .short('s')
                .long("sec")
                .takes_value(true)
                .help("Secret key"),
        )
        .arg(
            Arg::new("pub")
                .short('p')
                .long("pub")
                .takes_value(true)
                .help("Public key"),
        )
        .arg(
            Arg::new("out")
                .short('o')
                .long("out")
                .takes_value(true)
                .required(false)
                .help("b58 output for shared secret")
                .possible_values(["hex", "b58", "bip39"])
                .default_value("hex"),
        )
        .arg(
            Arg::new("length")
                .short('n')
                .long("length")
                .takes_value(true)
                .required(false)
                .help("Length of shared secret")
                .value_parser(value_parser!(u64).range(0..=max_hex_len() as u64)),
        )
        .arg(
            Arg::new("suffix")
                .short('u')
                .long("suffix")
                .takes_value(true)
                .required(false)
                .help("Suffix string")
                .default_value(""),
        )
        .get_matches();

    if args.value_of("out").unwrap() == "bip39"
        && (args.value_of("suffix").unwrap() != "" || args.get_one::<u64>("length").is_some())
    {
        println!("Options --length and --suffix are not compatible with bip39 output");
        std::process::exit(exitcode::DATAERR);
    }

    let suffix = args.value_of("suffix").unwrap();
    if suffix.len() > 8 {
        println!("Suffix can be at most length 8");
        std::process::exit(exitcode::DATAERR);
    }

    match args.value_of("mode") {
        Some("keypair") => {
            let (seckey, pubkey) = create_keypair();

            println!("sec: {}", seckey.to_hex());
            println!(
                "pub: {}{}",
                hex::encode(pubkey.x.to_bytes()),
                hex::encode(pubkey.y.to_bytes())
            );
        }
        Some("shared-secret") => {
            if !args.is_present("pub") || !args.is_present("sec") {
                println!("Missing required --pub and --sec arguments");
                std::process::exit(exitcode::DATAERR);
            }

            let seckey = ScalarField::from_hex(args.value_of("sec").unwrap()).unwrap();

            let pubkey_hex = args.value_of("pub").unwrap();
            if pubkey_hex.len() != max_hex_len() * 2 {
                println!("Invalid pub key");
                std::process::exit(exitcode::DATAERR);
            }

            let pubkey = CurvePoint::new(
                BaseField::from_hex(&pubkey_hex[0..max_hex_len()]).unwrap(),
                BaseField::from_hex(&pubkey_hex[max_hex_len()..]).unwrap(),
                false,
            );

            let shared_secret = create_shared_secret(seckey, pubkey);

            let len = match args.get_one::<u64>("length") {
                None => match args.value_of("out").unwrap() {
                    "hex" => max_hex_len(),
                    "b58" => max_b58_len(),
                    "bip39" => max_b58_len(),
                    _ => panic!("invalid output type"),
                },
                Some(length) => *length as usize,
            } - suffix.len();

            println!(
                "shared secret: {}",
                format_secret(shared_secret, args.value_of("out").unwrap(), len, suffix)
            );

            let shared_pubkey = compute_pubkey(shared_secret);

            if args.value_of("out").unwrap() != "hex" {
                println!(
                    "shared pubkey: {}{}",
                    bs58::encode(shared_pubkey.x.to_bytes()).into_string(),
                    bs58::encode(shared_pubkey.y.to_bytes()).into_string()
                );
            } else {
                println!(
                    "shared pubkey: {}{}",
                    hex::encode(shared_pubkey.x.to_bytes()),
                    hex::encode(shared_pubkey.y.to_bytes())
                );
            }
        }
        Some(&_) => panic!("Invalid mode"),
        None => panic!("Missing mode"),
    }
}

#[cfg(test)]
mod tests {
    use crate::{create_keypair, create_shared_secret, format_secret};
    use std::ops::Add;

    #[test]
    fn test_ok_shared_secret() {
        let (a_sec, a_pub) = create_keypair();
        let (b_sec, b_pub) = create_keypair();

        let a_secret = create_shared_secret(a_sec, b_pub);
        let b_secret = create_shared_secret(b_sec, a_pub);

        assert_eq!(a_secret, b_secret);
    }

    #[test]
    fn test_bad_shared_secret() {
        let (a_sec, a_pub) = create_keypair();
        let (b_sec, b_pub) = create_keypair();

        let b_pub2 = b_pub.add(a_pub);

        let a_secret = create_shared_secret(a_sec, b_pub2);
        let b_secret = create_shared_secret(b_sec, a_pub);

        assert_ne!(a_secret, b_secret);
    }

    #[test]
    #[should_panic]
    fn test_bad_b58_suffix() {
        let (a_sec, _a_pub) = create_keypair();
        let (_b_sec, b_pub) = create_keypair();
        let shared_secret = create_shared_secret(a_sec, b_pub);

        format_secret(shared_secret, "b58", 44, &"012345678");
    }

    #[test]
    #[should_panic]
    fn test_bad_b58_length() {
        let (a_sec, _a_pub) = create_keypair();
        let (_b_sec, b_pub) = create_keypair();
        let shared_secret = create_shared_secret(a_sec, b_pub);

        format_secret(shared_secret, "b58", 64, &"01234567");
    }

    #[test]
    #[should_panic]
    fn test_bad_hex_length() {
        let (a_sec, _a_pub) = create_keypair();
        let (_b_sec, b_pub) = create_keypair();
        let shared_secret = create_shared_secret(a_sec, b_pub);

        format_secret(shared_secret, "hex", 64, &"01234567");
    }

    #[test]
    fn test_ok_hex() {
        let (a_sec, _a_pub) = create_keypair();
        let (_b_sec, b_pub) = create_keypair();
        let shared_secret = create_shared_secret(a_sec, b_pub);

        let sec = format_secret(shared_secret, "hex", 12, &"^%");
        assert!(sec.len() == 14);
    }

    #[test]
    fn test_ok_b58() {
        let (a_sec, _a_pub) = create_keypair();
        let (_b_sec, b_pub) = create_keypair();
        let shared_secret = create_shared_secret(a_sec, b_pub);

        let sec = format_secret(shared_secret, "b58", 12, &"#!@");
        assert!(sec.len() == 15);
    }
}

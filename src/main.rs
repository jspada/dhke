#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

use std::str::FromStr;

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::UniformRand;
use clap::{value_parser, Arg, Command};
use hmac::{Hmac, KeyInit, Mac};
use mina_curves::pasta::Pallas as CurvePoint;
use num_bigint::BigUint;
use o1_utils::FieldHelpers;
use sha3::{Digest, Sha3_256};

type ScalarField = <CurvePoint as AffineCurve>::ScalarField;
type BaseField = <CurvePoint as AffineCurve>::BaseField;

fn max_alpha_len() -> usize {
    78
}

fn max_b10_len() -> usize {
    78
}

fn max_hex_len() -> usize {
    2 * ScalarField::size_in_bytes() + 2
}

fn max_b58_len() -> usize {
    // max length of 32bytes encoded as base58
    (ScalarField::size_in_bytes() as f32 * 8.0 / 58f32.log2()).ceil() as usize
}

fn max_bip39_len() -> usize {
    // refrigerator x 24 + 23
    311
}

fn max_len(mode: &str) -> usize {
    match mode {
        "alpha" => max_alpha_len(),
        "b10" => max_b10_len(),
        "hex" => max_hex_len(),
        "b58" => max_b58_len(),
        "bip39" => max_bip39_len(),
        _ => panic!("Invalid mode"),
    }
}

fn b10_to_alpha(b10: String) -> String {
    b10.chars()
        .map(|c| {
            let digit = c.to_digit(10).unwrap();
            let c = char::from_digit(digit + 10, 20).unwrap();
            if digit % 2 == 1 {
                c
            } else {
                c.to_uppercase().collect::<Vec<char>>()[0]
            }
        })
        .collect()
}

fn alpha_to_b10(alpha: String) -> String {
    alpha
        .chars()
        .map(|c| {
            let digit = c.to_lowercase().collect::<Vec<char>>()[0]
                .to_digit(20)
                .unwrap();
            char::from_digit(digit - 10, 10).unwrap()
        })
        .collect()
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
    ScalarField::from_bytes(&curve_point.x.to_bytes()).unwrap() // Change of field (I promise it's OK)
}

fn create_hd_secret(seckey: ScalarField, id: &str) -> ScalarField {
    let mut hmac = Hmac::<Sha3_256>::new_from_slice(&seckey.to_bytes()[..]).unwrap();
    hmac.update(id.as_bytes());
    let binding = hmac.finalize().clone();
    let mut bytes = [0; 32];
    bytes.copy_from_slice(binding.as_bytes());
    bytes[bytes.len() - 1] &= 0b0011_1111; // Convert to scalar field element
                                           // Note: Truncating like this creates an
                                           // insignificant amount of bias and is
                                           // simpler than reduction modulo p
    ScalarField::from_bytes(&bytes).unwrap()
}

fn format_bytes(bytes: &[u8], mode: &str) -> String {
    match mode {
        "alpha" => format!(
            "I{}",
            b10_to_alpha(BigUint::from_bytes_le(bytes).to_string())
        ),
        "b10" => BigUint::from_bytes_le(bytes).to_string(),
        "b58" => bs58::encode(bytes).into_string(),
        "hex" => format!("0x{}", hex::encode(bytes)),
        "bip39" => bip39::Mnemonic::from_entropy(bytes).unwrap().to_string(),
        _ => panic!("Invalid mode"),
    }
}

fn format_secret(
    secret: ScalarField,
    mode: &str,
    length: Option<u64>,
    suffix: Option<&str>,
) -> String {
    let secret_str = format_bytes(&secret.to_bytes(), mode);
    let suffix = suffix.unwrap_or("");
    if secret_str.len() < 4 * suffix.len() {
        panic!("Secret should be at least 4 times longer than suffix");
    }

    let length = length.unwrap_or((secret_str.len() - suffix.len()) as u64) as usize;
    if length > secret_str.len() {
        panic!("Length can be at most {}", secret_str.len());
    }

    if length + suffix.len() > max_len(mode) {
        panic!(
            "Maximum length possible is {}",
            max_len(mode) - suffix.len()
        );
    }

    secret_str[..length - suffix.len()].to_string() + suffix
}

fn format_pubkey(pubkey: CurvePoint, mode: &str) -> String {
    format_bytes(
        &pubkey
            .x
            .to_bytes()
            .into_iter()
            .chain(pubkey.y.to_bytes())
            .collect::<Vec<u8>>(),
        mode,
    )
}

fn format_checksum(pubkey: CurvePoint) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(
        pubkey
            .x
            .to_bytes()
            .into_iter()
            .chain(pubkey.y.to_bytes())
            .collect::<Vec<u8>>(),
    );
    format_bytes(&hasher.finalize()[0..4], "b58")
}

fn read_seckey(sec: &str) -> ScalarField {
    let mut mode = "";
    if sec.chars().all(|c| c.is_numeric()) {
        mode = "b10";
    }
    if sec.len() > 1 && sec.starts_with('I') && sec.chars().all(|c| "AbCdEfGhIj".contains(c)) {
        mode = "alpha";
    }
    if sec.len() > 2 && sec.starts_with("0x") && sec[2..].chars().all(|c| c.is_ascii_hexdigit()) {
        mode = "hex";
    }
    if sec
        .chars()
        .all(|c| "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(c))
    {
        println!("b58");
        mode = "b58";
    }
    let mnemonic: Vec<&str> = sec.split_whitespace().collect();
    if mnemonic
        .iter()
        .all(|w| bip39::Language::English.word_list().contains(w))
    {
        mode = "bip39";
    }

    match mode {
        "alpha" => ScalarField::from_biguint(
            &BigUint::from_str(&alpha_to_b10(sec[1..].to_string())).unwrap(),
        )
        .unwrap(),
        "b10" => ScalarField::from_biguint(&BigUint::from_str(sec).unwrap()).unwrap(),
        "hex" => ScalarField::from_hex(&sec[2..]).unwrap(),
        "b58" => ScalarField::from_bytes(&bs58::decode(sec).into_vec().unwrap()[..]).unwrap(),
        "bip39" => {
            ScalarField::from_bytes(&bip39::Mnemonic::from_str(sec).unwrap().to_entropy()).unwrap()
        }
        _ => panic!("Invalid secret format"),
    }
}

fn main() {
    let args = Command::new("dhke")
        .version("0.1.0")
        .author("Joseph Spadavecchia <joseph@redtrie.com>")
        .about("Diffie–Hellman key exchange")
        .arg(
            Arg::new("command")
                .takes_value(true)
                .required(true)
                .help("Command")
                .possible_values(["keypair", "pubkey", "shared-secret", "hd-secret"]),
        )
        .arg(
            Arg::new("mode")
                .short('m')
                .long("mode")
                .takes_value(true)
                .required(false)
                .help("Output mode")
                .possible_values(["hex", "alpha", "b10", "b58", "bip39"])
                .default_value("b58"),
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
            Arg::new("id")
                .short('i')
                .long("id")
                .takes_value(true)
                .required(false)
                .help("Unique identifier"),
        )
        .arg(
            Arg::new("length")
                .short('n')
                .long("length")
                .takes_value(true)
                .required(false)
                .help("Length of shared secret")
                .value_parser(value_parser!(u64).range(0..=max_bip39_len() as u64)),
        )
        .arg(
            Arg::new("suffix")
                .short('u')
                .long("suffix")
                .takes_value(true)
                .required(false)
                .help("Suffix string"),
        )
        .get_matches();

    let mode = args.value_of("mode").unwrap();

    let suffix = args.get_one::<String>("suffix").cloned();
    let suffix = suffix.as_deref();
    if let Some(suffix) = suffix {
        if suffix.len() > 8 {
            println!("Suffix can be at most length 8");
            std::process::exit(exitcode::DATAERR);
        }
    }

    let length = args.get_one::<u64>("length").cloned();

    match args.value_of("command") {
        Some("pubkey") => {
            if !args.is_present("sec") {
                println!("Missing required --sec argument");
                std::process::exit(exitcode::DATAERR);
            }

            if args.is_present("pub") {
                println!("Invalid option --pub");
                std::process::exit(exitcode::DATAERR);
            }

            if args.get_one::<u64>("length").is_some() {
                println!("Invalid option --length");
                std::process::exit(exitcode::DATAERR);
            }

            if args.is_present("suffix") {
                println!("Invalid option --suffix");
                std::process::exit(exitcode::DATAERR);
            }

            if args.get_one::<u64>("id").is_some() {
                println!("Invalid option --id");
                std::process::exit(exitcode::DATAERR);
            }

            if mode == "bip39" {
                println!("Cannot output pubkey with --mode bip39");
                std::process::exit(exitcode::DATAERR);
            }

            let seckey = read_seckey(args.value_of("sec").unwrap());
            let pubkey = compute_pubkey(seckey);

            println!("Pubkey: {}", format_pubkey(pubkey, mode));
        }
        Some("keypair") => {
            if args.get_one::<u64>("sec").is_some() {
                println!("Invalid option --sec");
                std::process::exit(exitcode::DATAERR);
            }

            if args.is_present("pub") {
                println!("Invalid option --pub");
                std::process::exit(exitcode::DATAERR);
            }

            if args.get_one::<u64>("id").is_some() {
                println!("Invalid option --id");
                std::process::exit(exitcode::DATAERR);
            }

            if args.get_one::<u64>("length").is_some() {
                println!("Invalid option --length");
                std::process::exit(exitcode::DATAERR);
            }

            if args.is_present("suffix") {
                println!("Invalid option --suffix");
                std::process::exit(exitcode::DATAERR);
            }

            let (seckey, pubkey) = create_keypair();

            println!("Seckey: {}", format_secret(seckey, mode, None, None));
            println!(
                "Pubkey: {}",
                format_pubkey(pubkey, if mode == "bip39" { "b58" } else { mode })
            );
        }
        Some("shared-secret") => {
            if !args.is_present("pub") {
                println!("Missing required --pub argument");
                std::process::exit(exitcode::DATAERR);
            }

            if !args.is_present("sec") {
                println!("Missing required --sec argument");
                std::process::exit(exitcode::DATAERR);
            }

            if args.is_present("id") {
                println!("Invalid option --id");
                std::process::exit(exitcode::DATAERR);
            }

            if length.is_some() {
                println!("Invalid option --length");
                std::process::exit(exitcode::DATAERR);
            }

            if suffix.is_some() {
                println!("Invalid option --suffix");
                std::process::exit(exitcode::DATAERR);
            }

            let seckey = read_seckey(args.value_of("sec").unwrap());

            let pubkey_hex = args.value_of("pub").unwrap();
            if pubkey_hex.len() != max_hex_len() * 2 - 2 {
                println!("Invalid pub key");
                std::process::exit(exitcode::DATAERR);
            }

            let pubkey = CurvePoint::new(
                BaseField::from_hex(&pubkey_hex[2..max_hex_len()]).unwrap(),
                BaseField::from_hex(&pubkey_hex[max_hex_len()..]).unwrap(),
                false,
            );

            let shared_secret = create_shared_secret(seckey, pubkey);

            println!(
                "Shared secret: {}",
                format_secret(shared_secret, mode, None, None)
            );

            let shared_pubkey = compute_pubkey(shared_secret);

            println!("Checksum:      {}", format_checksum(shared_pubkey));
        }
        Some("hd-secret") => {
            if !args.is_present("sec") {
                println!("Missing required --sec argument");
                std::process::exit(exitcode::DATAERR);
            }

            if args.is_present("pub") {
                println!("Invalid option --pub");
                std::process::exit(exitcode::DATAERR);
            }

            let seckey = read_seckey(args.value_of("sec").unwrap());

            if !args.is_present("id") {
                println!("Missing required --id argument");
                std::process::exit(exitcode::DATAERR);
            }

            if mode == "bip39" && (suffix.is_some() || length.is_some()) {
                println!("Options --length and --suffix are not compatible with bip39 output");
                std::process::exit(exitcode::DATAERR);
            }

            let id = args.value_of("id").unwrap();

            let hd_secret = create_hd_secret(seckey, id);

            println!(
                "HD secret: {}",
                format_secret(hd_secret, mode, length, suffix)
            );

            let hd_pubkey = compute_pubkey(hd_secret);

            print!("Params:    --id {}", id);
            if let Some(length) = length {
                print!(" --length {}", length)
            }
            if let Some(suffix) = suffix {
                print!(" --suffix {}", suffix)
            }
            println!(" --mode {}", mode);
            println!("Checksum:  {}", format_checksum(hd_pubkey));
        }
        Some(&_) => panic!("Invalid command"),
        None => panic!("Missing command"),
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

        format_secret(shared_secret, "b58", Some(44), Some("012345678"));
    }

    #[test]
    #[should_panic]
    fn test_bad_b58_length() {
        let (a_sec, _a_pub) = create_keypair();
        let (_b_sec, b_pub) = create_keypair();
        let shared_secret = create_shared_secret(a_sec, b_pub);

        format_secret(shared_secret, "b58", Some(64), Some("01234567"));
    }

    #[test]
    #[should_panic]
    fn test_bad_hex_length() {
        let (a_sec, _a_pub) = create_keypair();
        let (_b_sec, b_pub) = create_keypair();
        let shared_secret = create_shared_secret(a_sec, b_pub);

        format_secret(shared_secret, "hex", Some(64), Some("01234567"));
    }

    #[test]
    fn test_ok_hex() {
        let (a_sec, _a_pub) = create_keypair();
        let (_b_sec, b_pub) = create_keypair();
        let shared_secret = create_shared_secret(a_sec, b_pub);

        let sec = format_secret(shared_secret, "hex", Some(12), Some("^%"));
        assert!(sec.len() == 12);
    }

    #[test]
    fn test_ok_b58() {
        let (a_sec, _a_pub) = create_keypair();
        let (_b_sec, b_pub) = create_keypair();
        let shared_secret = create_shared_secret(a_sec, b_pub);
        let sec = format_secret(shared_secret, "b58", Some(12), Some("#!@"));
        assert!(sec.len() == 12);
    }
}

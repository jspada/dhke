#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::UniformRand;
use clap::{Arg, Command};
use mina_curves::pasta::Pallas as CurvePoint;
use o1_utils::FieldHelpers;

type ScalarField = <CurvePoint as AffineCurve>::ScalarField;
type BaseField = <CurvePoint as AffineCurve>::BaseField;

fn create_keypair() -> (ScalarField, CurvePoint) {
    let seckey = ScalarField::rand(&mut rand::rngs::OsRng);
    let pubkey: CurvePoint = CurvePoint::prime_subgroup_generator()
        .mul(seckey)
        .into_affine();
    (seckey, pubkey)
}

fn create_shared_secret(a_seckey: ScalarField, b_pubkey: CurvePoint) -> ScalarField {
    let curve_point = b_pubkey.mul(a_seckey).into_affine();
    ScalarField::from_bytes(&curve_point.x.to_bytes()).unwrap() // change of field (I promise it's OK)
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
        .get_matches();

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
            if pubkey_hex.len() != 128 {
                println!("Invalid pub key");
                std::process::exit(exitcode::DATAERR);
            }

            let pubkey = CurvePoint::new(
                BaseField::from_hex(&pubkey_hex[0..64]).unwrap(),
                BaseField::from_hex(&pubkey_hex[64..]).unwrap(),
                false,
            );

            let shared_secret = create_shared_secret(seckey, pubkey);

            println!("shared secret: {}", hex::encode(shared_secret.to_bytes()));
        }
        Some(&_) => panic!("Invalid mode"),
        None => panic!("Missing mode"),
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Add;

    use crate::{create_keypair, create_shared_secret};

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
}

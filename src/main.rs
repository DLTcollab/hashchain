extern crate clap;
extern crate openssl;
mod hashchain;

use clap::{value_t, App, AppSettings, Arg, SubCommand};
use hashchain::HashChain;
use openssl::base64::{decode_block, encode_block};
use std::process::exit;

fn main() {
    let matches = parse_cli();

    if let Some(matches) = matches.subcommand_matches("create") {
        let algo = matches.value_of("algo").unwrap_or("blake3");
        let base = value_t!(matches.value_of("index"), u32).unwrap_or(0);
        let length = value_t!(matches.value_of("length"), u32).unwrap_or(1);
        let seed = matches.value_of("seed").unwrap();
        hash_chain_create(seed, algo, base, length);
    } else if let Some(matches) = matches.subcommand_matches("verify") {
        let algo = matches.value_of("algo").unwrap_or("sha256");
        let query = matches.value_of("query").unwrap();
        let anchor = matches.value_of("anchor").unwrap();
        let range = value_t!(matches.value_of("max_range"), u32).unwrap_or(10);
        let result = hash_chain_verify(algo, query, anchor, range);
        if result {
            println!("success");
        } else {
            println!("failure");
            exit(1);
        }
    }
}

/// Create hashchain
///
/// # Arguments
///
/// * `seed`: Seed for initialization
/// * `algo`: Hashing algorithm
/// * `base`: The base index to start printing
/// * `len`: The number of hashchains to print
fn hash_chain_create(seed: &str, algo: &str, base: u32, len: u32) {
    let mut data = HashChain::init_seed(algo, seed.as_bytes());

    for i in 0..base + len + 1 {
        if i > base {
            let enc = encode_block(HashChain::convert(&data));
            println!("{}", enc);
        }
        data = HashChain::hash(data);
    }
}

/// Verify if two hashchains are in the same sequence
///
/// # Arguments
///
/// * `algo`: Hashing algorithm
/// * `query`: Query hash
/// * `anchor`: Tip hash
/// * `range`: Maximum check range for verification
fn hash_chain_verify(algo: &str, query: &str, anchor: &str, range: u32) -> bool {
    let qhash = decode_block(query).unwrap_or_else(|_| {
        println!("Invalid base64 string in query");
        exit(1)
    });
    let thash = decode_block(anchor).unwrap_or_else(|_| {
        println!("Invalid base64 string in anchor");
        exit(1)
    });

    let mut data = HashChain::init(algo, qhash.as_slice());
    let cmp = HashChain::init(algo, thash.as_slice());

    for _ in 0..range {
        data = HashChain::hash(data);
        if HashChain::equal(&data, &cmp) {
            return true;
        }
    }
    false
}

fn parse_cli<'a>() -> clap::ArgMatches<'a> {
    App::new("hashchain")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommand(
            SubCommand::with_name("create")
                .about("Create hashchain from given seed")
                .arg(
                    Arg::with_name("algo")
                        .short("a")
                        .long("algorithm")
                        .takes_value(true)
                        .help("Hash algorithm to use"),
                )
                .arg(
                    Arg::with_name("length")
                        .short("l")
                        .long("length")
                        .takes_value(true)
                        .help("The number of hash values to be generated"),
                )
                .arg(
                    Arg::with_name("index")
                        .short("i")
                        .long("index")
                        .takes_value(true)
                        .help("The base index to start"),
                )
                .arg(
                    Arg::with_name("seed")
                        .short("s")
                        .long("seed")
                        .takes_value(true)
                        .required(true)
                        .help("Seed for generating hash value"),
                ),
        )
        .subcommand(
            SubCommand::with_name("verify")
                .about("Verify if two hashes are in same chain")
                .arg(
                    Arg::with_name("algo")
                        .short("a")
                        .long("algorithm")
                        .takes_value(true)
                        .help("Hash algorithm to use"),
                )
                .arg(
                    Arg::with_name("query")
                        .short("q")
                        .long("query")
                        .takes_value(true)
                        .required(true)
                        .help("The query to be verified"),
                )
                .arg(
                    Arg::with_name("anchor")
                        .short("n")
                        .long("anchor")
                        .takes_value(true)
                        .required(true)
                        .help("The anchor to be verified"),
                )
                .arg(
                    Arg::with_name("max_range")
                        .short("r")
                        .long("range")
                        .takes_value(true)
                        .help("Maximum range to test"),
                ),
        )
        .get_matches()
}

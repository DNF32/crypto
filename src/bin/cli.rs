use std::{env, error::Error, fs::File, io};

use crypto::sha2::Sha256;

enum Alg {
    Sha256,
    Sha512,
}
impl std::str::FromStr for Alg {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sha256" => Ok(Self::Sha256),
            "sha512" => Ok(Self::Sha512),
            _ => Err(format!("unknown algorithm: {s}")),
        }
    }
}

struct Config {
    b_flag: bool,
    c_flag: bool,
    mine: bool,
    quiet_flag: bool,
    alg: Alg,
    files: Option<Vec<String>>,
}

fn parse_flag(args: Vec<String>) -> Result<Config, io::Error> {
    let mut b_flag = false;
    let mut c_flag = false;
    let mut mine = false;
    let mut alg = Alg::Sha256;
    let mut quiet_flag = false;
    let mut inputs: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "-b" {
            b_flag = true;
        } else if arg == "-c" {
            c_flag = true
        } else if arg == "--quiet" {
            quiet_flag = true
        } else if arg == "--mine" {
            mine = true
        } else if arg == "--algorithm" {
            let value = args
                .get(i + 1)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing algorithm"))?;

            alg = value
                .parse::<Alg>()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
            i += 1;
        } else {
            inputs.push(arg.to_string());
        }
        i += 1;
    }

    Ok(Config {
        b_flag: b_flag,
        c_flag: c_flag,
        quiet_flag: quiet_flag,
        mine: mine,
        alg: alg,
        files: if !inputs.is_empty() {
            Some(inputs)
        } else {
            None
        },
    })
}

struct ErrorCount {
    inc_format: u32,
    inc_digest: u32,
}

impl ErrorCount {
    fn new() -> Self {
        ErrorCount {
            inc_format: 0,
            inc_digest: 0,
        }
    }
}

fn parse_checksum_line(line: &str) -> Result<(&str, &str), String> {
    let (hash, rest) = line
        .split_once(" ")
        .ok_or_else(|| format!("Wrong format for line: {line}"))?;

    let file_path = rest
        .strip_prefix(" ")
        .or_else(|| rest.strip_prefix("*"))
        .ok_or_else(|| format!("Wrong format for line: {line}"))?;

    if hash.is_empty() || rest.is_empty() {
        return Err(format!("Wrong format for line: {}", line));
    };

    Ok((hash, file_path))
}

fn validate_file(path: &str, config: &Config, error: &mut ErrorCount) -> io::Result<()> {
    let checksum_file = File::open(path)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "could not open checksum file"));

    parse_check
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    let (config, file_paths) = parse_flag(args);

    let mut err = ErrorCount::new();

    match config.c_flag {
        false => {
            let out = file_paths
                .iter()
                .map(|file| file.digest_file(&config))
                .collect::<Vec<String>>()
                .join("\n");
            println!("{out}");
        }
        true => {
            let out = file_paths
                .iter()
                .map(|file| file.validate_file(&config, &mut err))
                .collect::<Vec<String>>()
                .join("\n");
            println!("{out}");
            if err.inc_format > 0 {
                println!(
                    "md5sum: WARNING: {} line is improperly formatted",
                    err.inc_format
                );
            }
            if err.inc_digest > 0 {
                println!(
                    "md5sum: WARNING: {} computed checksum did NOT match",
                    err.inc_digest
                );
            }
        }
    }
}


use chrono::prelude::*;
use lazy_static::lazy_static;
use regex::Regex;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fs::File;
use std::io::prelude::*;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::string::ToString;
use strum::EnumString;
use strum::ToString;
use walkdir::WalkDir;
use walkdir::DirEntry;
use std::path::Path;

use log::info;

#[derive(Copy, Clone, Debug, PartialEq, EnumString, ToString)]
pub enum DNSSecKeyType {
    KSK,
    ZSK,
}


#[derive(Clone, Debug)]
pub struct Secret {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug)]
pub struct DNSSecKey {
    pub name: String,
    pub key_id: String,
    pub zone: String,
    pub key_type: DNSSecKeyType,
    pub created: Option<DateTime<Utc>>,
    pub publish: Option<DateTime<Utc>>,
    pub activate: Option<DateTime<Utc>>,
    //pub revoke: DateTime<Utc>,
    pub inactive: Option<DateTime<Utc>>,
    //pub delete: DateTime<Utc>,
    pub_raw_bytes: Vec<u8>,
    priv_raw_bytes: Vec<u8>,
}

#[derive(Debug)]
pub enum ParseError {
    Exec(ExecErrorInfo),
    IO(std::io::Error),
    WalkDir(walkdir::Error),
}

pub fn parse_directory(dir: &Path) -> Result<Vec<DNSSecKey>, ParseError> {
    let walker = WalkDir::new(&dir).into_iter();
    let keys: Vec<(Secret, Secret)> = walker.filter_map(|entry| entry.map_err(|e| ParseError::WalkDir(e)).and_then(|e| {
        let public_path_with_extension = e.path().with_extension("key");
        let private_path_with_extension = e.path().with_extension("private");
        let public_file_name = public_path_with_extension.file_name().unwrap().to_str().unwrap();
        let private_file_name = private_path_with_extension.file_name().unwrap().to_str().unwrap();
        let public_key_content = std::fs::read_to_string(&public_path_with_extension);
        let private_key_content = std::fs::read_to_string(&private_path_with_extension);
        match public_key_content {
            Ok(pubkc) => {
                let public_key = Secret{
                    name: public_file_name.to_string(),
                    value: pubkc, 
                };
                private_key_content.map(move |privkc| {
                    (public_key, Secret{
                        name: private_file_name.to_string(),
                        value: privkc, 
                    })
                })
            },
            Err(e) => Err(e),
        }.map_err(|e| ParseError::IO(e))
    }).ok()).collect();

    let mut out = Vec::new();
    for k in keys {
       
       let (pu, pr) = k;
       out.push(parse(&pu, &pr)?);
    }
    Ok(out)
}

pub fn parse(pub_key: &Secret, priv_key: &Secret) -> Result<DNSSecKey, ParseError> {
    let mut fields: HashMap<String, String> = HashMap::new();

    lazy_static! {
        static ref DATES: Regex = Regex::new("([A-Za-z]+): ([0-9]{14})").unwrap();
        static ref KEY: Regex = Regex::new("([a-z.-]+) IN DNSKEY (256|257)").unwrap();
        static ref KEY_ID: Regex = Regex::new("keyid ([0-9]{1,5})").unwrap();
    }

    for l in BufReader::new(pub_key.value.as_bytes()).lines() {
        let l = l.unwrap();
        for cap in DATES.captures_iter(&l) {
            fields.insert(cap[1].to_string(), cap[2].to_string());
        }
        for cap in KEY.captures_iter(&l) {
            fields.insert("Zone".to_string(), cap[1].to_string());
            fields.insert("KeyType".to_string(), cap[2].to_string());
        }
        for cap in KEY_ID.captures_iter(&l) {
            fields.insert("KeyID".to_string(), cap[1].to_string());
        }
    }

    let name = remove_name_extension(&pub_key.name);

    Ok(DNSSecKey {
        name,
        key_id: fields.remove("KeyID").unwrap(),
        zone: fields.remove("Zone").unwrap(),
        key_type: match fields.remove("KeyType") {
            v if v.is_some() && v.as_ref().unwrap() == "256" => DNSSecKeyType::ZSK,
            v if v.is_some() && v.as_ref().unwrap() == "257" => DNSSecKeyType::KSK,
            _ => panic!("Could not parse key type"),
        },
        created: parse_date(fields.remove("Created")),
        publish: parse_date(fields.remove("Publish")),
        activate: parse_date(fields.remove("Activate")),
        inactive: parse_date(fields.remove("Inactive")),
        pub_raw_bytes: pub_key.value.as_bytes().to_vec(),
        priv_raw_bytes: priv_key.value.as_bytes().to_vec(),
    })
}

fn parse_date(input: Option<String>) -> Option<DateTime<Utc>> {
    input.and_then(|d| {
        Some(NaiveDateTime::parse_from_str(&d, "%Y%m%d%H%M%S").unwrap())
            .map(|d| DateTime::from_utc(d, Utc))
    })
}

use dbc_rust_modules::exec::ExecErrorInfo;
use dbc_rust_modules::exec::SpawnOk;
use dbc_rust_modules::exec::Wait;
use std::fs;
use std::process::Command;
use tempdir::TempDir;

pub fn new_dnssec_key_via_temp(
    zone: &str,
    key_type: DNSSecKeyType,
) -> Result<HashMap<String, String>, ExecErrorInfo> {
    dnssec_key_via_temp(zone, key_type, None)
}

pub fn successor_dnssec_key_via_temp(
    prev: &DNSSecKey,
) -> Result<HashMap<String, String>, ParseError> {
    dnssec_key_via_temp(&prev.zone.clone(), prev.key_type, Some(prev))
        .map_err(|e| ParseError::Exec(e))
}

fn dnssec_key_via_temp(
    zone: &str,
    key_type: DNSSecKeyType,
    prev_key: Option<&DNSSecKey>,
) -> Result<HashMap<String, String>, ExecErrorInfo> {
    let tmp_dir = TempDir::new("keys").unwrap();
    let bits: u16 = match key_type {
        DNSSecKeyType::KSK => 4096,
        DNSSecKeyType::ZSK => 2048,
    };
    let expiry_time = match key_type {
        DNSSecKeyType::KSK => "+2y",
        DNSSecKeyType::ZSK => "+6mo",
    };
    let tmp_dir_path = tmp_dir.path().to_str().unwrap();

    let mut cmd = Command::new("dnssec-keygen");
    let mut child = cmd.args(&["-K", tmp_dir_path, "-I", expiry_time]);

    if key_type == DNSSecKeyType::KSK {
        child = child.args(&["-f", "KSK"]);
    }
    let mut old_pub_key_path: Option<PathBuf> = None;
    let mut old_priv_key_path: Option<PathBuf> = None;
    child = match &prev_key {
        Some(k) => {
            let base_name = k.name.clone();
            old_pub_key_path = Some(tmp_dir.path().join(&format!("{}.key", &base_name)));
            old_priv_key_path =
                Some(tmp_dir.path().join(&format!("{}.private", &base_name)));
            {
                let mut pub_key =
                    File::create(old_pub_key_path.as_ref().unwrap()).unwrap();
                pub_key.write_all(&k.pub_raw_bytes).unwrap();
                let mut priv_key =
                    File::create(old_priv_key_path.as_ref().unwrap()).unwrap();
                priv_key.write_all(&k.priv_raw_bytes).unwrap();
            }
            child.args(&["-S", &base_name])
        }
        None => child.args(&[
            "-a",
            "RSASHA512",
            "-b",
            &bits.to_string(),
            "-n",
            "ZONE",
            zone,
        ]),
    };

    child.spawn_ok()?.wait()?;

    old_pub_key_path.map(|p| fs::remove_file(p).unwrap());
    old_priv_key_path.map(|p| fs::remove_file(p).unwrap());

    let mut key_parts: HashMap<String, String> = HashMap::new();
    let paths = fs::read_dir(tmp_dir.path()).unwrap();
    for path in paths {
        let path = path.unwrap();
        if path.file_type().unwrap().is_file() {
            key_parts.insert(
                path.file_name().to_str().unwrap().to_string(),
                fs::read_to_string(path.path()).unwrap(),
            );
        }
    }

    Ok(key_parts)
}

pub fn remove_name_extension(name: &str) -> String {
    let mut path_split: Vec<&str> = name.split(".").collect();
    let last_part = path_split.pop().unwrap_or(name);
    if last_part == "key" || last_part == "private" {
        path_split.join(".")
    } else {
        name.to_string()
    }
}

/* Example key below */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        let pub_key = Secret{
          name: "foo.pub".to_string(),
          value: "
            ; This is a zone-signing key, keyid 44426, for foo.bar.
            ; Created: 20211006124643 (Wed Oct  6 14:46:43 2021)
            ; Publish: 20211006124643 (Wed Oct  6 14:46:43 2021)
            ; Activate: 20211006124643 (Wed Oct  6 14:46:43 2021)
            ; Revoke: 20211016125139 (Sat Oct 16 14:51:39 2021)
            ; Inactive: 20211016125226 (Sat Oct 16 14:52:26 2021)
            ; Delete: 20211016125206 (Sat Oct 16 14:52:06 2021)
            foo.bar. IN DNSKEY 256 3 10 AwEAAaQjWIQqvSwDz9+TWy17z6GwbfF/N4qcvOh3sSUBmx1lADkDYo9P Ksg3jlWVlyRvQp8gihOHTGyXDfHaoeN4TlB1ngC73sOCoyRfiEaBZM K3xzGTzsvY0=
          ".to_string(),
        };
        let priv_key = Secret {
            name: "foo.private".to_string(),
            value: "not important for this test".to_string(),
        };

        println!("{:?}", &parse(&pub_key, &priv_key).unwrap());
    }
}

/*
Example key below

; This is a zone-signing key, keyid 44426, for foo.bar.
; Created: 20211006124643 (Wed Oct  6 14:46:43 2021)
; Publish: 20211006124643 (Wed Oct  6 14:46:43 2021)
; Activate: 20211006124643 (Wed Oct  6 14:46:43 2021)
; Revoke: 20211016125139 (Sat Oct 16 14:51:39 2021)
; Inactive: 20211016125226 (Sat Oct 16 14:52:26 2021)
; Delete: 20211016125206 (Sat Oct 16 14:52:06 2021)
foo.bar. IN DNSKEY 256 3 10 AwEAAaQjWIQqvSwDz9+TWy17z6GwbfF/N4qcvOh3sSUBmx1lADkDYo9P Ksg3jlWVlyRvQp8gihOHTGyXDfHaoeN4TlB1ngC73sOCoyRfiEaBZM K3xzGTzsvY0=
*/

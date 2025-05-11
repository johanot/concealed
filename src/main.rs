use log::{debug, error, info, warn, trace};
use crate::config::{Config, Zone, Record};
use crate::keyparser::DNSSecKey;

use std::io::BufReader;
use std::fs::File;
use std::io::Write;
use std::process::Command;
use std::process::Stdio;
use std::path::Path;
use rand::{distr::Alphanumeric, Rng};

use warp::Filter;

use askama::Template;
use std::path::PathBuf;
use std::io::BufRead;

use chrono::Utc;
use chrono::NaiveDateTime;

use sha2::{Sha256, Digest};
use regex::Regex;

use lazy_static::lazy_static;
use std::collections::{HashMap, HashSet};
use tokio::sync::RwLock;
use chrono::Duration;
use clap::{command, arg};
use serde_derive::Deserialize;
use config::Condition;
use tokio::task::JoinSet;

use std::convert::Infallible;
use reqwest::Client;

mod config;
mod keyparser;

lazy_static! {
    static ref ZONES: RwLock<HashMap<String, Zone>> =
        RwLock::new(HashMap::new());

    static ref UNKNOWN_STATE_INDEX: std::sync::RwLock<HashSet<Record>> =
        std::sync::RwLock::new(HashSet::new());
}

#[derive(Debug, Deserialize)]
struct FaythePayload {
  records: HashMap<String, FaytheRecord>,
}


#[derive(Debug, Deserialize)]
struct FaytheRecord {
  #[serde(rename = "type")]
  #[allow(dead_code)]
  record_type: FaytheRecordType,
  content: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
enum FaytheRecordType {
  TXT,
}

#[derive(Debug)]
enum RecordOrApex {
    Record(String),
    Apex,
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let args = command!()
        .arg(
            arg!(configcheck: "Parses Concealed config file and exits")
                .long("config-check")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            arg!(config: "Path to Concealed JSON config file")
                .long("config")
                .help("Path to Concealed JSON config file")
                .required(true),
        );

    let m = args.get_matches();

    let config_check = m.get_flag("configcheck");
    let config_file = m.get_one::<String>("config").unwrap().to_owned();
    let file = File::open(&config_file).unwrap();
    let reader = BufReader::new(file);
    let config: Config = serde_json::from_reader(reader).unwrap();

    if config_check {
        std::process::exit(0);
    }

    let mut set = JoinSet::new();

    // for each record with condition, spawn a task to monitor the condition
    // and update the record if the condition changes
    for (zone_name, zone) in &config.zones {
        for record in &zone.apex {
            if let Some(condition) = &record.condition {
                UNKNOWN_STATE_INDEX.write().unwrap().insert(record.clone());
                let record_or_apex = RecordOrApex::Apex;
                set.spawn(condition_monitor(config.clone(), zone_name.clone(), record_or_apex, record.clone(), condition.clone()));
            }
        }
        for (record_name, records) in &zone.records {
            for record in records {
                if let Some(condition) = &record.condition {
                    UNKNOWN_STATE_INDEX.write().unwrap().insert(record.clone());
                    let record_or_apex = RecordOrApex::Record(record_name.clone());
                    set.spawn(condition_monitor(config.clone(), zone_name.clone(), record_or_apex, record.clone(), condition.clone()));
                }
            }
        }
    }

    {
        let mut guard = ZONES.write().await;
        for (n, z) in &config.zones {
            guard.insert(n.clone(), z.to_owned());
        }
    }
    set.spawn(reconcile_zones(config.clone()));
    set.spawn(spawn_api_server(config.clone()));

    set.join_all().await;
}

#[derive(Debug)]
enum TransitionStatus {
    Unknown,
    Up,
    GoingDown { failures: u32 },
    GoingUp { successes: u32 },
    Down,
}

async fn condition_monitor(config: Config, zone_name: String, record_or_apex: RecordOrApex, record: Record, condition: Condition) {
    let mut transition_status = TransitionStatus::Unknown;

    let update_transition_status = |status: &mut TransitionStatus, success: bool, threshold: u32, r: &mut Record| -> bool {
       let mut status_known_now = false;
       match status {
            TransitionStatus::Unknown => {
                if success {
                    *status = TransitionStatus::GoingUp { successes: 1 };
                } else {
                    *status = TransitionStatus::GoingDown { failures: 1 };
                }
            },
            TransitionStatus::Up => {
                if success {
                    *status = TransitionStatus::Up;
                } else {
                    *status = TransitionStatus::GoingDown { failures: 1 };
                }
            },
            TransitionStatus::GoingDown { failures } => {
                if !success && *failures >= threshold {
                    *status = TransitionStatus::Down;
                    info!("transitioned zone: {}, record target: {} to state DOWN", zone_name, r.target);
                    r.enabled = false;
                    status_known_now = true;
                } else if !success {
                    *status = TransitionStatus::GoingDown { failures: *failures + 1 };
                } else {
                    *status = TransitionStatus::GoingUp { successes: 1 };
                }
            },
            TransitionStatus::GoingUp { successes } => {
                if success && *successes >= threshold {
                    *status = TransitionStatus::Up;
                    info!("transitioned zone: {}, record target: {} to state UP", zone_name, r.target);
                    r.enabled = true;
                    status_known_now = true;
                } else if success {
                    *status = TransitionStatus::GoingUp { successes: *successes + 1 };
                } else {
                    *status = TransitionStatus::GoingDown { failures: 1 };
                }
            },
            TransitionStatus::Down => {
                if success {
                    *status = TransitionStatus::GoingUp { successes: 1 };
                } else {
                    *status = TransitionStatus::Down;
                }
            },
        }
        debug!("updating transition status: {:?}, success: {}, threshold: {}", status, success, threshold);
        status_known_now
    };

    match condition {
        config::Condition::Http { url, status, timeout, interval, transition } => {
            info!("monitoring condition for zone: {}, {:?}, url: {}, status: {}, timeout: {}, interval: {}", zone_name, record_or_apex, url, status, timeout, interval);
            loop {
                let client = Client::builder()
                    .timeout(std::time::Duration::from_secs(timeout as u64))
                    .build()
                    .unwrap();

                match client
                    .get(url.to_owned())
                    .send()
                    .await {
                    Ok(response) => {
                        let mut guard =
                            ZONES
                            .write()
                            .await;

                        let zone = guard
                            .get_mut(&zone_name)
                            .unwrap();

                        match &record_or_apex {
                            RecordOrApex::Record(record_name) => {
                                zone
                                .records
                                .get_mut(record_name)
                                .unwrap()
                                .iter_mut()
                                .find(|r| r.target == record.target && r.record_type == record.record_type)
                                .map(|r| {
                                    debug!("condition for: {:?}, response status: {}", record_or_apex, response.status().as_u16());
                                    let state_known_now = update_transition_status(&mut transition_status, response.status().as_u16() == status, transition.repeat, r);
                                    if !UNKNOWN_STATE_INDEX.read().unwrap().is_empty() {
                                        let mut guard = UNKNOWN_STATE_INDEX.write().unwrap();
                                        if state_known_now {
                                            guard.remove(r);
                                        }
                                    }
                                });
                            },
                            RecordOrApex::Apex => {
                                zone
                                .apex
                                .iter_mut()
                                .find(|r| r.target == record.target && r.record_type == record.record_type)
                                .map(|r| {
                                    debug!("condition for: {:?}, response status: {}", record_or_apex, response.status().as_u16());
                                    let state_known_now = update_transition_status(&mut transition_status, response.status().as_u16() == status, transition.repeat, r);
                                    if !UNKNOWN_STATE_INDEX.read().unwrap().is_empty() {
                                        let mut guard = UNKNOWN_STATE_INDEX.write().unwrap();
                                        if state_known_now {
                                            guard.remove(r);
                                        }
                                    }
                                });
                            },
                        }
                    },
                    Err(e) => {
                        error!("condition for: {:?}, failed with error: {:?}", record_or_apex, e);
                        let mut guard =
                            ZONES
                            .write()
                            .await;

                        let zone = guard
                            .get_mut(&zone_name)
                            .unwrap();

                        match &record_or_apex {
                            RecordOrApex::Record(record_name) => {
                                zone
                                .records
                                .get_mut(record_name)
                                .unwrap()
                                .iter_mut()
                                .find(|r| r.target == record.target && r.record_type == record.record_type)
                                .map(|r| {
                                    let state_known_now = update_transition_status(&mut transition_status, false, transition.repeat, r);
                                    if !UNKNOWN_STATE_INDEX.read().unwrap().is_empty() {
                                        let mut guard = UNKNOWN_STATE_INDEX.write().unwrap();
                                        if state_known_now {
                                            guard.remove(r);
                                        }
                                    }
                                });
                            },
                            RecordOrApex::Apex => {
                                zone
                                .apex
                                .iter_mut()
                                .find(|r| r.target == record.target && r.record_type == record.record_type)
                                .map(|r| {
                                    let state_known_now = update_transition_status(&mut transition_status, false, transition.repeat, r);
                                    if !UNKNOWN_STATE_INDEX.read().unwrap().is_empty() {
                                        let mut guard = UNKNOWN_STATE_INDEX.write().unwrap();
                                        if state_known_now {
                                            guard.remove(r);
                                        }
                                    }
                                });
                            },
                        }
                    }
                }
                let actual_interval = match &transition_status {
                    TransitionStatus::GoingDown { .. } | TransitionStatus::GoingUp { .. } => transition.interval,
                    _ => interval,
                };
                tokio::time::sleep(tokio::time::Duration::from_secs(actual_interval as u64)).await;
            }
        }
    }
}

async fn reconcile_zones(config: Config) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));

    let mut reload_cmd = config.named_reload_command
        .as_ref()
        .map(|c| {
            let (reload_cmd_str, args) = c.split_first().unwrap();
            let mut cmd = Command::new(reload_cmd_str);
            cmd.stderr(Stdio::inherit())
                .stdout(Stdio::inherit())
                .args(args);

            cmd
        });

    loop {
        debug!("unknown state conditions: {}", UNKNOWN_STATE_INDEX.read().unwrap().len());
        if UNKNOWN_STATE_INDEX.read().unwrap().is_empty() {
            std::fs::create_dir_all(&config.zone_file_dir.canonicalize().unwrap()).unwrap();
            let now = Utc::now();
            let serial = now.timestamp() as u32;
            let mut reload_needed = false;

            {
                let guard = ZONES.read().await;
                for (n, z) in guard.iter() {
                    let (active_keys, prepub_keys): (Vec<DNSSecKey>, Vec<DNSSecKey>) = check_dnssec_key_validity(&n, &z).await;
                    let (content, digest) = render_zonefile(&n, &z, serial);
                    let changed = maybe_persist(&config, &n, &content, &digest);
                    let signed = maybe_sign(&config, &n, &z, &digest, changed, active_keys, prepub_keys);
                    reload_needed = reload_needed || changed || signed;
                }
            }

            if reload_cmd.is_some() && reload_needed {
                let reload_cmd = reload_cmd.as_mut().unwrap();
                info!("executing reload command: {:?}", &reload_cmd);
                let status = reload_cmd.status().unwrap();
                if !status.success() {
                    error!("named reload failed with exit code: {:?}", &status.code());
                }
            }
        } else {
            warn!("cannot update zone: waiting for all conditions to be known ...");
        }
        interval.tick().await;
    }
}

async fn check_dnssec_key_validity(name: &str, zone: &Zone) -> (Vec<DNSSecKey>,Vec<DNSSecKey>) {
    if let Some(dir) = &zone.dnssec_key_directory {
        let keys = match keyparser::parse_directory(&dir) {
            Ok(keys) => keys,
            Err(e) => {
                error!("failed to parse key directory: {:?}", &e);
                vec!()
            },
        };
        let now = Utc::now();
        let newest_renewal_candidate =
            keys
                .iter()
                .filter(|k| {
                    k.key_type == keyparser::DNSSecKeyType::ZSK  // Only auto-renew ZSK's for now
                })
                .max_by(|x, y| {
                    if x.inactive.is_some() && y.inactive.is_some() {
                        x.inactive.unwrap().cmp(&y.inactive.unwrap())
                    } else {
                        std::cmp::Ordering::Greater
                    }
                });

        match newest_renewal_candidate {
            Some(k) => {
                debug!("considering dnssec key: {}", &k.name);
                if k.inactive.is_some() && now.checked_add_signed(Duration::try_days(45).unwrap()).unwrap() > k.inactive.unwrap() {
                    info!("renewing dnssec-key for zone: {}, key-name: {}", &name, &k.name);
                    let key_parts = keyparser::successor_dnssec_key_via_temp(&k).unwrap();
                    for (k, v) in &key_parts {
                        let final_path = dir.join(&k);
                        let mut file = File::create(&final_path).unwrap();
                        file.write_all(&v.as_bytes()).unwrap();
                    }
                }
            }
            None => {},
        }

        let active_keys = keys
            .iter()
            .filter(|k| {
                k.key_type == keyparser::DNSSecKeyType::ZSK &&
                k.activate.map(|a| a < now).unwrap_or(false) &&
                k.inactive.map(|i| i > now).unwrap_or(true)
            })
            .map(|k| k.to_owned())
            .collect();

        let prepub_keys = keys
            .iter()
            .filter(|k| {
                k.publish.map(|p| p < now).unwrap_or(false) &&
                k.inactive.map(|i| i > now).unwrap_or(true)
            })
            .map(|k| k.to_owned())
            .collect();

        (active_keys, prepub_keys)
    } else {
        (vec!(), vec!())
    }
}

async fn insert_record(name: &str, record: &FaytheRecord) -> Result<(), String> {
    let name = name.trim_end_matches('.');
    let zm = ZONES.read().await.iter().find(|(n, _)| {
        name.ends_with(n.as_str())
    })
    .map(|(n, _)| {
        n.to_owned()
    });

    if let Some(zone) = zm {
        let zone = zone.trim_end_matches('.');
        let name = name.strip_suffix(zone).unwrap_or(name);
        let name = name.trim_end_matches('.');

        let mut guard = ZONES.write().await;
        let records = &mut guard
            .get_mut(zone)
            .unwrap()
            .records;

        match &record.content {
            Some(c) => {
                let new_record = Record{
                    target: c.to_owned(),
                    ttl_seconds: 300,
                    record_type: "TXT".to_string(),
                    priority: None,
                    condition: None,
                    enabled: true,
                };

                //always override whatever records that might exist
                records.insert(name.to_owned(), vec!(new_record));
                Ok(())
            },
            None => Err("No content in record".to_string()),
        }
    } else {
        Err("Not authority for zone".to_string())
    }
}

async fn spawn_api_server(config: Config) {
    let hello = warp::put()
        .and(warp::path!("faythe"))
        .and(warp::body::content_length_limit(1024 * 16))
        .and(warp::body::json())
        .and_then(|payload: FaythePayload| async move {
            let mut error_messages = vec!();
            for (name, record) in &payload.records {
                match insert_record(&name, &record).await {
                    Ok(_) => {},
                    Err(msg) => error_messages.push(msg),
                }
            }
            Ok::<std::string::String, Infallible>(error_messages.join("\n"))
        });

    warp::serve(hello)
        .run((config.api.listen_addr, config.api.listen_port))
        .await;
}

fn render_zonefile(name: &str, zone: &Zone, serial: u32) -> (String, String) {

    #[derive(Template)]
    #[template(path = "template.zone", escape = "none")]
    struct ZoneTemplate<'a> {
        name: &'a str,
        zone: &'a Zone,
        serial: u32,
    }

    let template_normalized = ZoneTemplate{
        name,
        zone,
        serial: 0,
    };
    let normalized_rendered = template_normalized.render().unwrap();
    let mut hasher = Sha256::new();
    hasher.update(normalized_rendered.as_bytes());
    let digest = format!("{:x}", hasher.finalize());

    let template = ZoneTemplate{
        name,
        zone,
        serial,
    };

    (template.render().unwrap(), digest)
}

fn maybe_persist(config: &Config, name: &str, content: &str, digest: &str) -> bool {
    let zone_file_dir = config.zone_file_dir.canonicalize().unwrap();
    let final_path = zone_file_dir.join(format!("{}.zone", &name));
    let temp_path = zone_file_dir.join(format!("{}.zone", &digest));

    let link_target = std::fs::read_link(&final_path).unwrap_or(PathBuf::new());

    if link_target != temp_path || !link_target.exists() {
        info!("symlinking new zonefile: {}, {}", &name, &digest);
        let mut f = File::create(&temp_path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        symlink_in_place(&temp_path, &final_path);
        true
    } else {
        trace!("not changing symlink: {:?}", &temp_path);
        false
    }
}

fn maybe_sign(config: &Config, name: &str, zone: &Zone, digest: &str, upstream_changes: bool, active_keys: Vec<DNSSecKey>, prepub_keys: Vec<DNSSecKey>) -> bool {
    match &zone.dnssec_key_directory {
        Some(key_dir) => {
            let zone_file_dir = config.zone_file_dir.canonicalize().unwrap();

            let final_path = zone_file_dir.join(format!("{}.zone", &digest));
            let signed_temp_path = zone_file_dir.join(format!("{}.signed", &digest));
            let signed_final_path = zone_file_dir.join(format!("{}.signed", &name));
            let signed_link_target = std::fs::read_link(&signed_final_path).unwrap_or(PathBuf::new());

            if upstream_changes ||
                !signed_link_target.exists() ||
                signed_link_target != signed_temp_path ||
                find_nearest_rrsig_expiry(&signed_link_target, active_keys, prepub_keys) < 60*60*24*7 // 7 days
            {
                let mut cmd = Command::new("dnssec-signzone");

                cmd.stderr(Stdio::inherit())
                .stdout(Stdio::inherit())
                .arg("-N")
                .arg("unixtime")
                .arg("-T")
                .arg("300") // TTL
                .arg("-t")
                .arg("-o")
                .arg(&name)
                .arg("-f")
                .arg(&signed_temp_path)
                .arg("-K")
                .arg(&key_dir)
                .arg("-S")
                .arg(&final_path);

                info!("executing: {:?}", &cmd);

                let status = cmd.status().unwrap();

                if status.success() {
                    symlink_in_place(&signed_temp_path, &signed_final_path);
                    info!("sucessfully signed zone: {} to output path: {:?}", &name, &signed_final_path);
                } else {
                    error!("dnssec signing failed for zone: {} with exit code: {:?}", &name, &status.code());
                }
                true
            } else {
                debug!("not changing symlink: {:?}", &signed_temp_path);
                false
            }
        },
        None => false  // dnssec disabled for zone
    }
}

fn symlink_in_place(from: &Path, to: &Path) {
    let dir = to.parent().unwrap();

    let s: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(7)
        .map(char::from)
        .collect();

    let temp_path = dir.join(s);
    std::os::unix::fs::symlink(from, &temp_path).unwrap();
    std::fs::rename(&temp_path, &to).unwrap();
}

fn find_nearest_rrsig_expiry(path: &Path, active_keys_input: Vec<DNSSecKey>, prepub_keys_input: Vec<DNSSecKey>) -> i64 {

    let mut active_keys = HashMap::new();
    for k in active_keys_input {
        active_keys.insert(k.key_id.clone(), k.clone());
    }
    let mut prepub_keys = HashMap::new();
    for k in prepub_keys_input {
        prepub_keys.insert(k.key_id.clone(), k.clone());
    }

    let re_pre = Regex::new(r"^[^\s]*\s+[0-9]+\s+RRSIG.+").unwrap();
    let re_now = Regex::new(r"^\s+([0-9]{14}) [0-9]{14} ([0-9]{1,5})").unwrap();
    let re_prepub = Regex::new(r"key id = ([0-9]{1,5})").unwrap();
    let utc = Utc::now();
    let now = utc.naive_utc();

    let file = File::open(path).unwrap();
    let lines = std::io::BufReader::new(file).lines();
    let mut rrsig_upcoming = false;
    let mut soonest_expiry = i64::MAX;
    let mut line_number = 0;
    for line in lines {
        line_number = line_number+1;
        let current_expiry = if let Ok(l) = line {
            if let Some(m) = re_prepub.captures(&l) {
                if let Some(key_id) = m.get(1) {
                    debug!("removing key-id (prepub): '{}'", &key_id.as_str());
                    prepub_keys.remove(key_id.as_str());
                }
            }
            if rrsig_upcoming {
                rrsig_upcoming = false;
                if let Some(m) = re_now.captures(&l) {
                    if let Some(key_id) = m.get(2) {
                        debug!("removing key-id (active): '{}'", &key_id.as_str());
                        active_keys.remove(key_id.as_str());
                    }
                    if let Some(expiry_string) = m.get(1) {
                        debug!("trying to date-parse: '{}'", expiry_string.as_str());
                        let parsed = NaiveDateTime::parse_from_str(expiry_string.as_str(), "%Y%m%d%H%M%S").unwrap();
                        parsed.signed_duration_since(now).num_seconds()
                    } else {
                        warn!("parse error, rrsig string time parsable: {}, line: {}", &l, line_number);
                        0
                    }
                } else {
                    warn!("parse error, rrsig string not matching: {}, line: {}", &l, line_number);
                    0
                }
            } else {
                rrsig_upcoming = re_pre.is_match(&l);
                i64::MAX
            }
        } else {
            warn!("read error, no line to read");
            0
        };
        if current_expiry < soonest_expiry {
            soonest_expiry = current_expiry;
        }
    }
    if active_keys.len() > 0 {
        let key_ids: Vec<String> = active_keys.values().map(|k| k.key_id.clone()).collect();
        info!("forcing expiry of signed zone now, since there is ACTIVE keys which doesn't have RRSIG records for keyid's: {:?}", &key_ids);
        0
    } else if prepub_keys.len() > 0 {
        let key_ids: Vec<String> = prepub_keys.values().map(|k| k.key_id.clone()).collect();
        info!("forcing expiry of signed zone now, since there is PREPUB keys which doesn't have DNSKEY records for keyid's: {:?}", &key_ids);
        0
    } else {
        soonest_expiry
    }
}


use serde_derive::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
pub struct Config {
  #[serde(default = "default_api_tcp_listen_port")]
  pub api_tcp_listen_port: u16,
  pub named_reload_command: Vec<String>,
  pub zones: HashMap<String, Zone>,
  pub zone_file_dir: PathBuf,
}

fn default_api_tcp_listen_port() -> u16 {
  8053
}

#[derive(Debug, Deserialize)]
pub struct Zone {
  pub apex: Vec<Record>,
  #[serde(rename = "dnssecKeyDirectory")]
  pub dnssec_key_directory: Option<PathBuf>,
  pub records: HashMap<String, Vec<Record>>,
  //SOA stuff
  pub server: String,
  pub expire: String,
  pub refresh: String,
  pub retry: String,
  pub ttl: String,
}

#[derive(Debug, Deserialize)]
pub struct Record {
  pub target: String,
  #[serde(rename = "ttlSeconds")]
  pub ttl_seconds: u32,
  #[serde(rename = "type")]
  pub record_type: String,
  pub priority: Option<u32>,
}


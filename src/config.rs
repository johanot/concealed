
use serde_derive::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::net::Ipv4Addr;
use indexmap::map::IndexMap;

#[derive(Debug, Deserialize)]
pub struct Config {
  pub api: APIConfig,
  pub named_reload_command: Option<Vec<String>>,
  pub zones: HashMap<String, Zone>,
  pub zone_file_dir: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
pub struct APIConfig {
  pub listen_addr: Ipv4Addr,
  #[serde(default = "default_api_listen_port")]
  pub listen_port: u16,
}

fn default_api_listen_port() -> u16 {
  8053
}

#[derive(Clone, Debug, Deserialize)]
pub struct Zone {
  pub apex: Vec<Record>,
  #[serde(rename = "dnssecKeyDirectory")]
  pub dnssec_key_directory: Option<PathBuf>,
  pub records: IndexMap<String, Vec<Record>>,
  //SOA stuff
  pub server: String,
  pub expire: String,
  pub refresh: String,
  pub retry: String,
  pub ttl: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Record {
  pub target: String,
  #[serde(rename = "ttlSeconds")]
  pub ttl_seconds: u32,
  #[serde(rename = "type")]
  pub record_type: String,
  pub priority: Option<u32>,
}

impl Record {
  pub fn trailing_dot(&self) -> bool {
    match self.record_type.as_str() {
      "A" | "AAAA" | "TXT" => false,
      _ => true,
    }
  }
}

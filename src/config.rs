
use serde_derive::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::net::Ipv4Addr;
use indexmap::map::IndexMap;
use reqwest::Url;
use serde::{Deserialize, Deserializer};

#[derive(Clone, Debug, Deserialize)]
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
  pub condition: Option<Condition>,
  #[serde(default = "default_enabled")]
  pub enabled: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub enum Condition {
  #[serde(rename = "http")]
  Http {
    #[serde(deserialize_with = "deserialize_url")]
    url: Url,
    status: u16,
    timeout: u16,
    interval: u16,
    transition: Transition,
  },
}


fn default_enabled() -> bool {
  true
}

fn deserialize_url<'de, D>(data: D) -> Result<Url, D::Error> where D: Deserializer<'de>,
{
  let s: String = Deserialize::deserialize(data)?;
  Url::parse(&s).map_err(serde::de::Error::custom)
}

#[derive(Clone, Debug, Deserialize)]
pub struct Transition {
  pub interval: u16,
  pub repeat: u32,
}

impl Record {
  pub fn trailing_dot(&self) -> bool {
    match self.record_type.as_str() {
      "A" | "AAAA" | "TXT" => false,
      _ => true,
    }
  }
}

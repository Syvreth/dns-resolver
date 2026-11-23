//! TTL-aware DNS cache
//!
//! Stores resolved records with their TTL and expiry time.
//! Used to avoid redundant queries during resolution.

use crate::packet::RecordType;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct CacheEntry {
    pub ips: Vec<(String, Option<String>)>,
    ns_ips: Vec<String>,
    ns_names: Vec<String>,
    cnames: Vec<String>,
    rcode: u8,
    expiry: u64,
}

impl CacheEntry {
    fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now >= self.expiry
    }
}

pub struct DnsCache {
    cache: HashMap<String, CacheEntry>,
}

impl DnsCache {
    pub fn new() -> Self {
        DnsCache {
            cache: HashMap::new(),
        }
    }

    fn key(domain: &str, qtype: RecordType) -> String {
        format!("{}:{}", domain.to_lowercase(), qtype)
    }

    pub fn get(&self, domain: &str, qtype: RecordType) -> Option<&CacheEntry> {
        self.cache
            .get(&Self::key(domain, qtype))
            .filter(|e| !e.is_expired())
    }

    pub fn get_ips(&self, domain: &str, qtype: RecordType) -> Option<Vec<(String, Option<String>)>> {
        self.get(domain, qtype)
            .map(|e| e.ips.clone())
    }

    pub fn get_ns_ips(&self, ns_name: &str) -> Option<Vec<String>> {
        self.get(ns_name, RecordType::A)
            .map(|e| e.ns_ips.clone())
    }

    pub fn set(&mut self, domain: &str, qtype: RecordType, ips: Vec<(String, Option<String>)>, ttl: u32) {
        let entry = self
            .cache
            .entry(Self::key(domain, qtype))
            .or_insert_with(|| CacheEntry {
                ips: Vec::new(),
                ns_ips: Vec::new(),
                ns_names: Vec::new(),
                cnames: Vec::new(),
                rcode: 0,
                expiry: 0,
            });
        entry.ips = ips;
        entry.expiry = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + ttl as u64;
    }

    pub fn set_ns_ips(&mut self, ns_name: &str, ips: Vec<String>, ttl: u32) {
        let entry = self
            .cache
            .entry(Self::key(ns_name, RecordType::A))
            .or_insert_with(|| CacheEntry {
                ips: Vec::new(),
                ns_ips: Vec::new(),
                ns_names: Vec::new(),
                cnames: Vec::new(),
                rcode: 0,
                expiry: 0,
            });
        entry.ns_ips = ips;
        entry.expiry = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + ttl as u64;
    }

    pub fn get_cnames(&self, domain: &str) -> Option<Vec<String>> {
        self.get(domain, RecordType::CNAME)
            .map(|e| e.cnames.clone())
    }

    pub fn set_cname(&mut self, domain: &str, target: String, ttl: u32) {
        let entry = self
            .cache
            .entry(Self::key(domain, RecordType::CNAME))
            .or_insert_with(|| CacheEntry {
                ips: Vec::new(),
                ns_ips: Vec::new(),
                ns_names: Vec::new(),
                cnames: Vec::new(),
                rcode: 0,
                expiry: 0,
            });
        entry.cnames.push(target);
        entry.expiry = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + ttl as u64;
    }

    pub fn get_rcode(&self, domain: &str, qtype: RecordType) -> Option<u8> {
        self.get(domain, qtype)
            .map(|e| e.rcode)
    }

    pub fn set_rcode(&mut self, domain: &str, qtype: RecordType, rcode: u8, ttl: u32) {
        let entry = self
            .cache
            .entry(Self::key(domain, qtype))
            .or_insert_with(|| CacheEntry {
                ips: Vec::new(),
                ns_ips: Vec::new(),
                ns_names: Vec::new(),
                cnames: Vec::new(),
                rcode: 0,
                expiry: 0,
            });
        entry.rcode = rcode;
        entry.expiry = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + ttl as u64;
    }
}
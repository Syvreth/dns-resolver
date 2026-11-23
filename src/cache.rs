//! TTL-aware DNS cache
//!
//! Three separate stores, each entry with its own expiry:
//! - answers:  (name, type) -> addresses   (also used for nameserver addresses / glue)
//! - cnames:   name -> alias target
//! - nxdomain: names known not to exist (negative caching)
//!
//! Keeping them separate means one kind of entry can never hide or overwrite another.

use crate::packet::RecordType;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// TTL used for negative (NXDOMAIN) entries.
pub const NEGATIVE_TTL: u32 = 300;

struct Entry<T> {
    value: T,
    expires: Instant,
}

impl<T> Entry<T> {
    fn new(value: T, ttl: u32) -> Self {
        Entry { value, expires: Instant::now() + Duration::from_secs(ttl as u64) }
    }

    fn is_live(&self) -> bool {
        Instant::now() < self.expires
    }
}

pub type Answers = Vec<(String, Option<String>)>;

#[derive(Default)]
pub struct DnsCache {
    answers: HashMap<(String, u16), Entry<Answers>>,
    cnames: HashMap<String, Entry<String>>,
    nxdomain: HashMap<String, Entry<()>>,
}

fn norm(name: &str) -> String {
    name.trim_end_matches('.').to_lowercase()
}

impl DnsCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Cached addresses for (name, type), if present and not expired.
    pub fn get_answer(&self, name: &str, qtype: RecordType) -> Option<Answers> {
        self.answers
            .get(&(norm(name), qtype.to_u16()))
            .filter(|e| e.is_live() && !e.value.is_empty())
            .map(|e| e.value.clone())
    }

    /// Replace the cached addresses for (name, type).
    pub fn put_answer(&mut self, name: &str, qtype: RecordType, answers: Answers, ttl: u32) {
        if ttl == 0 || answers.is_empty() {
            return;
        }
        self.answers.insert((norm(name), qtype.to_u16()), Entry::new(answers, ttl));
    }

    /// Add one address to (name, type) without dropping the others (used for glue records,
    /// which arrive one address per record). The entry keeps the shortest TTL seen.
    pub fn add_address(&mut self, name: &str, qtype: RecordType, addr: String, ttl: u32) {
        if ttl == 0 {
            return;
        }
        let key = (norm(name), qtype.to_u16());
        let fresh = Entry::new(Vec::new(), ttl);
        let entry = self.answers.entry(key).or_insert_with(|| Entry::new(Vec::new(), ttl));
        if !entry.is_live() {
            *entry = fresh;
        } else if fresh.expires < entry.expires {
            entry.expires = fresh.expires;
        }
        if !entry.value.iter().any(|(a, _)| *a == addr) {
            entry.value.push((addr, None));
        }
    }

    pub fn get_cname(&self, name: &str) -> Option<String> {
        self.cnames
            .get(&norm(name))
            .filter(|e| e.is_live())
            .map(|e| e.value.clone())
    }

    pub fn put_cname(&mut self, name: &str, target: &str, ttl: u32) {
        if ttl == 0 {
            return;
        }
        self.cnames.insert(norm(name), Entry::new(target.to_string(), ttl));
    }

    pub fn is_nxdomain(&self, name: &str) -> bool {
        self.nxdomain.get(&norm(name)).is_some_and(|e| e.is_live())
    }

    pub fn put_nxdomain(&mut self, name: &str, ttl: u32) {
        if ttl == 0 {
            return;
        }
        self.nxdomain.insert(norm(name), Entry::new((), ttl));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ips(list: &[&str]) -> Answers {
        list.iter().map(|s| (s.to_string(), None)).collect()
    }

    #[test]
    fn answer_round_trip_is_case_and_dot_insensitive() {
        let mut c = DnsCache::new();
        c.put_answer("Example.COM.", RecordType::A, ips(&["1.2.3.4"]), 60);
        assert_eq!(c.get_answer("example.com", RecordType::A), Some(ips(&["1.2.3.4"])));
        assert_eq!(c.get_answer("example.com", RecordType::AAAA), None);
    }

    #[test]
    fn nameserver_resolved_as_answer_is_found_later() {
        // The old bug: a name resolved as an answer looked "cached but empty" when it was
        // looked up again as a nameserver, so the nameserver was skipped.
        let mut c = DnsCache::new();
        c.put_answer("ns-1404.awsdns-47.org", RecordType::A, ips(&["205.251.197.124"]), 172800);
        assert_eq!(
            c.get_answer("ns-1404.awsdns-47.org", RecordType::A),
            Some(ips(&["205.251.197.124"]))
        );
    }

    #[test]
    fn glue_addresses_accumulate_without_duplicates() {
        let mut c = DnsCache::new();
        c.add_address("a.gtld-servers.net", RecordType::A, "192.5.6.30".into(), 172800);
        c.add_address("a.gtld-servers.net", RecordType::A, "192.5.6.31".into(), 172800);
        c.add_address("a.gtld-servers.net", RecordType::A, "192.5.6.30".into(), 172800);
        assert_eq!(
            c.get_answer("a.gtld-servers.net", RecordType::A),
            Some(ips(&["192.5.6.30", "192.5.6.31"]))
        );
    }

    #[test]
    fn stores_do_not_collide() {
        let mut c = DnsCache::new();
        c.put_cname("www.example.com", "cdn.example.net", 60);
        c.put_nxdomain("nope.example.com", 60);
        assert_eq!(c.get_answer("www.example.com", RecordType::A), None);
        assert_eq!(c.get_cname("www.example.com").as_deref(), Some("cdn.example.net"));
        assert!(c.is_nxdomain("nope.example.com"));
        assert!(!c.is_nxdomain("www.example.com"));
    }

    #[test]
    fn zero_ttl_is_not_cached_and_entries_expire() {
        let mut c = DnsCache::new();
        c.put_answer("zero.example", RecordType::A, ips(&["9.9.9.9"]), 0);
        assert_eq!(c.get_answer("zero.example", RecordType::A), None);

        // Force an entry into the past to check expiry.
        c.put_answer("old.example", RecordType::A, ips(&["8.8.8.8"]), 60);
        c.answers.get_mut(&("old.example".into(), 1)).unwrap().expires =
            Instant::now() - Duration::from_secs(1);
        assert_eq!(c.get_answer("old.example", RecordType::A), None);
    }
}

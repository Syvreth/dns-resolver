//! TTL-aware DNS cache
//!
//! Three separate stores, each entry with its own expiry:
//! - answers:  (name, type) -> addresses   (also used for nameserver addresses / glue)
//! - cnames:   name -> alias target
//! - nxdomain: names known not to exist (negative caching)
//! - delegations: zone -> nameserver IPs learned from referrals, so a lookup can start at
//!   the closest known zone instead of the root
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
    delegations: HashMap<String, Entry<Vec<String>>>,
}

/// Canonical form of a name: lowercase, without a trailing dot (the root is "").
pub fn norm(name: &str) -> String {
    name.trim_end_matches('.').to_lowercase()
}

/// True if `name` is `zone` or lies below it. Every name lies below the root ("").
pub fn in_zone(name: &str, zone: &str) -> bool {
    let (name, zone) = (norm(name), norm(zone));
    zone.is_empty() || name == zone || name.ends_with(&format!(".{zone}"))
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

    /// Replace the nameserver IPs cached for `zone` (used for referrals that carry glue).
    pub fn put_delegation(&mut self, zone: &str, servers: Vec<String>, ttl: u32) {
        if ttl == 0 || servers.is_empty() {
            return;
        }
        self.delegations.insert(norm(zone), Entry::new(servers, ttl));
    }

    /// Add one nameserver IP to `zone` without dropping the others (used when a referral has
    /// no glue and its nameserver names are resolved one at a time). Like `add_address`, the
    /// entry keeps the shortest TTL seen.
    pub fn add_delegation_server(&mut self, zone: &str, server: String, ttl: u32) {
        if ttl == 0 {
            return;
        }
        let fresh = Entry::new(Vec::new(), ttl);
        let entry = self
            .delegations
            .entry(norm(zone))
            .or_insert_with(|| Entry::new(Vec::new(), ttl));
        if !entry.is_live() {
            *entry = fresh;
        } else if fresh.expires < entry.expires {
            entry.expires = fresh.expires;
        }
        if !entry.value.contains(&server) {
            entry.value.push(server);
        }
    }

    /// The deepest zone with live cached nameservers that contains `name`, walking up one
    /// label at a time (cf.x.amazon.com -> x.amazon.com -> amazon.com -> com), with its
    /// nameserver IPs. `None` means start from the root.
    pub fn closest_delegation(&self, name: &str) -> Option<(String, Vec<String>)> {
        let name = norm(name);
        let mut zone = name.as_str();
        while !zone.is_empty() {
            if let Some(entry) = self.delegations.get(zone).filter(|e| e.is_live() && !e.value.is_empty()) {
                return Some((zone.to_string(), entry.value.clone()));
            }
            zone = zone.split_once('.').map_or("", |(_, parent)| parent);
        }
        None
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

    fn servers(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn closest_delegation_walks_up_the_labels() {
        let mut c = DnsCache::new();
        c.put_delegation("com", servers(&["192.5.6.30"]), 172800);
        c.put_delegation("amazon.com", servers(&["205.251.193.8"]), 172800);
        c.put_delegation("47cf2c8c9-frontier.amazon.com.", servers(&["205.251.197.124"]), 300);

        assert_eq!(
            c.closest_delegation("CF.47cf2c8c9-frontier.amazon.com"),
            Some(("47cf2c8c9-frontier.amazon.com".into(), servers(&["205.251.197.124"])))
        );
        assert_eq!(
            c.closest_delegation("www.amazon.com"),
            Some(("amazon.com".into(), servers(&["205.251.193.8"])))
        );
        // The zone's own name starts at that zone's servers.
        assert_eq!(
            c.closest_delegation("amazon.com"),
            Some(("amazon.com".into(), servers(&["205.251.193.8"])))
        );
        assert_eq!(c.closest_delegation("example.com"), Some(("com".into(), servers(&["192.5.6.30"]))));
        assert_eq!(c.closest_delegation("example.org"), None);
        // A label boundary is required: "notamazon.com" is not under "amazon.com".
        assert_eq!(c.closest_delegation("notamazon.com").map(|(z, _)| z).as_deref(), Some("com"));
    }

    #[test]
    fn expired_delegation_falls_through_to_the_parent() {
        let mut c = DnsCache::new();
        c.put_delegation("com", servers(&["192.5.6.30"]), 172800);
        c.put_delegation("amazon.com", servers(&["205.251.193.8"]), 172800);
        c.delegations.get_mut("amazon.com").unwrap().expires = Instant::now() - Duration::from_secs(1);
        assert_eq!(c.closest_delegation("www.amazon.com").map(|(z, _)| z).as_deref(), Some("com"));
    }

    #[test]
    fn delegation_servers_accumulate_and_glue_replaces() {
        let mut c = DnsCache::new();
        c.add_delegation_server("example.com", "1.1.1.1".into(), 300);
        c.add_delegation_server("example.com", "2.2.2.2".into(), 300);
        c.add_delegation_server("example.com", "1.1.1.1".into(), 300);
        assert_eq!(c.closest_delegation("example.com").unwrap().1, servers(&["1.1.1.1", "2.2.2.2"]));

        c.put_delegation("example.com", servers(&["3.3.3.3"]), 300);
        assert_eq!(c.closest_delegation("example.com").unwrap().1, servers(&["3.3.3.3"]));

        // Zero TTL and empty server lists are never cached.
        c.put_delegation("zero.example", servers(&["4.4.4.4"]), 0);
        c.put_delegation("empty.example", Vec::new(), 300);
        assert_eq!(c.closest_delegation("zero.example"), None);
        assert_eq!(c.closest_delegation("empty.example"), None);
    }

    #[test]
    fn in_zone_respects_label_boundaries() {
        assert!(in_zone("www.amazon.com", "amazon.com"));
        assert!(in_zone("Amazon.COM.", "amazon.com"));
        assert!(in_zone("anything.example", ""));
        assert!(!in_zone("notamazon.com", "amazon.com"));
        assert!(!in_zone("com", "amazon.com"));
    }
}

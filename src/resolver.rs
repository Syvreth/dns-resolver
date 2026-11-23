//! DNS Recursive Resolver
//!
//! Implements iterative DNS resolution. Each lookup starts at the closest zone whose
//! nameservers are cached (or at the root servers) and follows referrals down the hierarchy.

use crate::cache::{in_zone, norm, DnsCache, NEGATIVE_TTL};
use crate::packet::*;
use crate::transport::*;
use std::collections::HashSet;

/// Known root DNS server addresses (IPv4)
const ROOT_SERVERS: &[&str] = &[
    "198.41.0.4",
    "170.247.170.2",
    "192.33.4.12",
    "199.7.91.13",
    "192.203.230.10",
    "192.5.5.241",
    "192.112.36.4",
    "198.97.190.53",
    "192.36.148.17",
    "192.58.128.30",
    "193.0.14.129",
    "199.7.83.42",
    "202.12.27.33",
];

/// Prefix of the error returned when a name does not exist.
const NXDOMAIN: &str = "NXDOMAIN";
/// Prefix of the error returned when a name exists but has no records of the asked type.
const NODATA: &str = "NODATA";
/// Prefix of the error returned when a lookup goes too deep.
const DEPTH_EXCEEDED: &str = "Resolution depth exceeded";

struct QueryState {
    domain: String,
    qtype: RecordType,
    depth: u32,
    /// The zone the servers being asked are authoritative for ("" for the root).
    zone: String,
    visited: HashSet<String>,
}

/// Errors that asking other servers won't change: the answer itself, or a runaway lookup.
fn is_final(error: &str) -> bool {
    error.starts_with(NXDOMAIN) || error.starts_with(NODATA) || error.starts_with(DEPTH_EXCEEDED)
}

/// A referral's zone is cached only if it contains the name being resolved and lies strictly
/// below the zone of the servers that sent it, so a lame or misbehaving server can't plant
/// nameservers for an unrelated zone or for a parent such as "com". Names are normalised.
fn may_cache_delegation(zone: &str, domain: &str, current_zone: &str) -> bool {
    zone != current_zone && in_zone(domain, zone) && in_zone(zone, current_zone)
}

fn resolve_step(
    state: &mut QueryState,
    servers: &[&str],
    cache: &mut DnsCache,
) -> Result<Vec<(String, Option<String>)>, String> {
    state.depth += 1;

    if state.depth > 20 {
        return Err(format!("{} for {}", DEPTH_EXCEEDED, state.domain));
    }

    // Check the cache before sending anything
    if cache.is_nxdomain(&state.domain) {
        println!("DEBUG: Cache hit: {} does not exist (NXDOMAIN)", state.domain);
        return Err(format!("{} for {}", NXDOMAIN, state.domain));
    }
    if let Some(ips) = cache.get_answer(&state.domain, state.qtype) {
        println!("DEBUG: Cache hit for {} ({}) - {} address(es)", state.domain, state.qtype, ips.len());
        return Ok(ips);
    }
    if let Some(target) = cache.get_cname(&state.domain) {
        println!("DEBUG: Cache hit: CNAME {} -> {}", state.domain, target);
        return resolve_inner(&target, state.qtype, cache, state.depth);
    }

    let mut last_error = String::new();

    for server in servers {
        let server_str = server.to_string();
        if state.visited.contains(&server_str) {
            continue;
        }
        state.visited.insert(server_str.clone());

        let query_id = rand::random::<u16>();
        let query = build_query(query_id, &state.domain, state.qtype, Some(4096));

        let response = match send_query_with_retries(&server_str, &query, 1500, 2) {
            Ok(response) => {
                println!("DEBUG: Querying {} for {} - got {} bytes", server_str, state.domain, response.len());
                response
            }
            Err(e) => {
                last_error = format!("Query to {} failed: {}", server_str, e);
                println!("DEBUG: {}", last_error);
                continue;
            }
        };

        let mut msg = match parse_message(&response) {
            Ok(msg) => {
                println!("DEBUG: Parsed response from {} - QR={} RCODE={:?} TC={} Questions={} Answers={} Authority={} Additional={}", 
                    server_str, msg.header.qr, msg.header.rcode, msg.header.tc,
                    msg.header.question_count, msg.header.answer_count,
                    msg.header.authority_count, msg.header.additional_count);
                msg
            }
            Err(e) => {
                last_error = format!("Failed to parse response from {}: {}", server_str, e);
                println!("DEBUG: {}", last_error);
                continue;
            }
        };

        if msg.header.id != query_id {
            last_error = format!("Response ID mismatch from {} (expected {}, got {})", 
                server_str, query_id, msg.header.id);
            println!("DEBUG: {}", last_error);
            continue;
        }

        // Check for truncated response - retry over TCP
        if msg.header.tc {
            println!("DEBUG: TC flag set from {}, retrying over TCP", server_str);
            match send_query_tcp(&server_str, &query, 3000) {
                Ok(tcp_response) => {
                    println!("DEBUG: TCP retry from {} - got {} bytes", server_str, tcp_response.len());
                    match parse_message(&tcp_response) {
                        Ok(tcp_msg) => {
                            if tcp_msg.header.id != query_id {
                                println!("DEBUG: TCP response ID mismatch");
                                continue;
                            }
                            println!("DEBUG: TCP retry successful from {}", server_str);
                            msg = tcp_msg;
                        }
                        Err(e) => {
                            println!("DEBUG: Failed to parse TCP response: {}", e);
                            continue;
                        }
                    }
                }
                Err(e) => {
                    println!("DEBUG: TCP retry failed: {}", e);
                    continue;
                }
            }
        }

        // Cache glue: A records in the additional section for the nameservers named in authority
        {
            let ns_names: Vec<String> = find_authority_ns_records(&msg)
                .iter()
                .map(|n| n.to_lowercase())
                .collect();
            for record in &msg.additional {
                if record.rtype == RecordType::A && ns_names.contains(&record.name.to_lowercase()) {
                    if let Some(ip) = record.get_ip() {
                        cache.add_address(&record.name, RecordType::A, ip, record.ttl);
                    }
                }
            }
        }

        match msg.header.rcode {
            Rcode::NoError => {}
            Rcode::NameError => {
                cache.put_nxdomain(&state.domain, NEGATIVE_TTL);
                return Err(format!("{} for {}", NXDOMAIN, state.domain));
            }
            Rcode::ServerFailure => {
                last_error = format!("SERVFAIL from {} for {}", server_str, state.domain);
                continue;
            }
            _ => {
                last_error = format!("Unexpected RCODE from {} for {}", server_str, state.domain);
                continue;
            }
        }

        // Check for answer records matching our query
        let results = find_ip_records(&msg, &state.domain);
        if !results.is_empty() {
            println!("DEBUG: Found {} IP records for {}", results.len(), state.domain);
            for (ip, _) in &results {
                println!("DEBUG:   {}", ip);
            }
            // Cache the answer with minimum TTL from response
            {
                let ttl = find_min_ttl(&msg);
                println!("DEBUG: Caching {} -> {} (TTL {})", state.domain, results.len(), ttl);
                cache.put_answer(&state.domain, state.qtype, results.clone(), ttl);
            }
            return Ok(results);
        }

        // Check for CNAME in answer section
        let cname_records = find_cname_records(&msg, &state.domain);
        if let Some(cname_target) = cname_records.first() {
            println!("DEBUG: CNAME {} -> {}", state.domain, cname_target);
            // Cache the CNAME
            {
                let ttl = find_min_ttl(&msg);
                println!("DEBUG: Caching CNAME {} -> {} (TTL {})", state.domain, cname_target, ttl);
                cache.put_cname(&state.domain, cname_target, ttl);
            }
            // The CNAME may point into a different zone, so start over from the closest
            // cached zone for the target (or the root)
            return resolve_inner(cname_target, state.qtype, cache, state.depth);
        }

        // Check for referral (NS records in authority section)
        let ns_records = find_authority_ns_records(&msg);
        if !ns_records.is_empty() {
            println!("DEBUG: Found {} NS records in authority (referral)", ns_records.len());
            for ns in &ns_records {
                println!("DEBUG:   NS: {}", ns);
            }

            // The zone being delegated to, with its NS TTL, if it is one we may cache.
            // The queries below go to that zone's servers whether or not it is cached.
            let delegation = find_referral_zone(&msg)
                .map(|(zone, ttl)| (norm(&zone), ttl))
                .filter(|(zone, _)| may_cache_delegation(zone, &norm(&state.domain), &state.zone));
            let child_zone = delegation
                .as_ref()
                .map_or_else(|| state.zone.clone(), |(zone, _)| zone.clone());

            // Look for NS server addresses in additional section
            let ns_ips = find_additional_ns_ips(&msg, &ns_records);
            if !ns_ips.is_empty() {
                println!("DEBUG: Found {} NS IPs in additional section", ns_ips.len());
                for ip in &ns_ips {
                    println!("DEBUG:   {}", ip);
                }
                if let Some((zone, ttl)) = &delegation {
                    println!("DEBUG: Caching delegation {} -> {} server(s) (TTL {})", zone, ns_ips.len(), ttl);
                    cache.put_delegation(zone, ns_ips.clone(), *ttl);
                }

                let ns_refs: Vec<&str> = ns_ips.iter().map(|s| s.as_str()).collect();
                let mut new_state = QueryState {
                    domain: state.domain.clone(),
                    qtype: state.qtype,
                    depth: state.depth,
                    zone: child_zone,
                    visited: HashSet::new(),
                };
                return resolve_step(&mut new_state, &ns_refs, cache);
            }
            
            // If no IPs in additional section, resolve NS names one at a time and
            // try querying each as soon as it resolves (lazy resolution).
            println!("DEBUG: No NS IPs in additional section, trying NS names one at a time");
            for ns_name in &ns_records {
                println!("DEBUG: Trying to resolve NS: {}", ns_name);
                
                // Shares the cache (a cached address comes back without any query) and
                // carries the current depth, so circular delegations still hit the depth limit.
                let resolved_ips = match resolve_inner(ns_name, RecordType::A, cache, state.depth) {
                    Ok(results) => results,
                    Err(e) => {
                        println!("DEBUG: Failed to resolve NS {}: {}", ns_name, e);
                        continue;
                    }
                };
                if let Some((zone, ttl)) = &delegation {
                    for (ip, _) in &resolved_ips {
                        println!("DEBUG: Caching delegation {} -> {} via {} (TTL {})", zone, ip, ns_name, ttl);
                        cache.add_delegation_server(zone, ip.clone(), *ttl);
                    }
                }

                for (ip, _) in resolved_ips {
                    println!("DEBUG: Resolved NS {} -> {}, trying to query", ns_name, ip);
                    let mut new_state = QueryState {
                        domain: state.domain.clone(),
                        qtype: state.qtype,
                        depth: state.depth,
                        zone: child_zone.clone(),
                        visited: HashSet::new(),
                    };
                    let servers: Vec<&str> = vec![&ip];
                    match resolve_step(&mut new_state, &servers, cache) {
                        Ok(found) => {
                            println!("DEBUG: Got answer via {}", ip);
                            return Ok(found);
                        }
                        // The zone's own nameserver says the name doesn't exist: stop here.
                        Err(e) if e.starts_with(NXDOMAIN) => return Err(e),
                        Err(e) => {
                            println!("DEBUG: Failed via {}: {}", ip, e);
                        }
                    }
                }
            }
            // If none of the NS names worked, try next server
        } else {
            // No NS referral - check if this is an authoritative "no data" response
            if has_soa_for_domain(&msg, &state.domain) {
                return Err(format!("{} for {}: no {} records", NODATA, state.domain, state.qtype));
            }
            last_error = format!("No answer, no referral from {} for {}", server_str, state.domain);
            continue;
        }
    }

    Err(format!("Failed to resolve {}: {}", state.domain, last_error))
}

/// Resolve `domain` starting at `depth` (0 for a fresh lookup). Starts at the closest zone
/// whose nameservers are cached, and falls back to the root servers if nothing is cached or
/// none of the cached servers can answer.
fn resolve_inner(
    domain: &str,
    qtype: RecordType,
    cache: &mut DnsCache,
    depth: u32,
) -> Result<Vec<(String, Option<String>)>, String> {
    let new_state = |zone: &str| QueryState {
        domain: domain.to_string(),
        qtype,
        depth,
        zone: zone.to_string(),
        visited: HashSet::new(),
    };

    if let Some((zone, servers)) = cache.closest_delegation(domain) {
        println!("DEBUG: Starting {} at cached zone {} ({} server(s))", domain, zone, servers.len());
        let server_refs: Vec<&str> = servers.iter().map(|s| s.as_str()).collect();
        match resolve_step(&mut new_state(&zone), &server_refs, cache) {
            Err(e) if !is_final(&e) => {
                println!("DEBUG: Cached servers for {} failed ({}), falling back to the root", zone, e);
            }
            result => return result,
        }
    }

    resolve_step(&mut new_state(""), ROOT_SERVERS, cache)
}

pub fn resolve_debug(domain: &str, qtype: RecordType) -> Result<Vec<(String, Option<String>)>, String> {
    println!("=== Resolving {} ({:?}) ===", domain, qtype);
    let mut cache = DnsCache::new();
    let result = resolve_inner(domain, qtype, &mut cache, 0)?;
    println!("=== Resolution complete ===");
    Ok(result)
}

fn find_min_ttl(msg: &Message) -> u32 {
    let mut min_ttl = 3600; // Default 1 hour if no TTL found
    for record in &msg.answers {
        if record.ttl < min_ttl {
            min_ttl = record.ttl;
        }
    }
    min_ttl
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delegations_are_cached_only_below_the_current_zone_and_above_the_name() {
        // Normal referrals: root -> com -> amazon.com -> 47cf2c8c9-frontier.amazon.com
        assert!(may_cache_delegation("com", "www.amazon.com", ""));
        assert!(may_cache_delegation("amazon.com", "www.amazon.com", "com"));
        assert!(may_cache_delegation(
            "47cf2c8c9-frontier.amazon.com",
            "tp.47cf2c8c9-frontier.amazon.com",
            "amazon.com"
        ));
        // A zone equal to the name itself is fine.
        assert!(may_cache_delegation("amazon.com", "amazon.com", "com"));

        // A zone that doesn't contain the name.
        assert!(!may_cache_delegation("example.org", "www.amazon.com", "com"));
        // An upward or sideways referral from a lame server.
        assert!(!may_cache_delegation("com", "www.amazon.com", "amazon.com"));
        assert!(!may_cache_delegation("amazon.com", "www.amazon.com", "amazon.com"));
        assert!(!may_cache_delegation("other.com", "x.other.com", "amazon.com"));
    }

    #[test]
    fn only_answers_and_runaway_lookups_are_final() {
        assert!(is_final("NXDOMAIN for nope.example"));
        assert!(is_final("NODATA for example.com: no AAAA records"));
        assert!(is_final("Resolution depth exceeded for loop.example"));
        assert!(!is_final("Failed to resolve example.com: Query to 1.2.3.4 failed: timed out"));
    }
}

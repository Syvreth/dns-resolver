//! DNS Recursive Resolver
//!
//! Implements iterative DNS resolution starting from root servers.
//! Follows referrals through the DNS hierarchy to resolve domain names.

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

struct QueryState {
    domain: String,
    qtype: RecordType,
    depth: u32,
    visited: HashSet<String>,
}

pub fn resolve(domain: &str, qtype: RecordType) -> Result<Vec<(String, Option<String>)>, String> {
    let mut state = QueryState {
        domain: domain.to_string(),
        qtype,
        depth: 0,
        visited: HashSet::new(),
    };
    resolve_step(&mut state, ROOT_SERVERS)
}

pub fn resolve_debug(domain: &str, qtype: RecordType) -> Result<Vec<(String, Option<String>)>, String> {
    println!("=== Resolving {} ({:?}) ===", domain, qtype);
    let mut state = QueryState {
        domain: domain.to_string(),
        qtype,
        depth: 0,
        visited: HashSet::new(),
    };
    let result = resolve_step(&mut state, ROOT_SERVERS)?;
    println!("=== Resolution complete ===");
    Ok(result)
}

fn resolve_step(
    state: &mut QueryState,
    servers: &[&str],
) -> Result<Vec<(String, Option<String>)>, String> {
    state.depth += 1;

    if state.depth > 20 {
        return Err(format!("Resolution depth exceeded for {}", state.domain));
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

        match msg.header.rcode {
            Rcode::NoError => {}
            Rcode::NameError => {
                return Err(format!("NXDOMAIN for {}", state.domain));
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
            return Ok(results);
        }

        // Check for CNAME in answer section
        let cname_records = find_cname_records(&msg, &state.domain);
        if let Some(cname_target) = cname_records.first() {
            println!("DEBUG: CNAME {} -> {}", state.domain, cname_target);
            let mut new_state = QueryState {
                domain: cname_target.clone(),
                qtype: state.qtype,
                depth: state.depth,
                visited: HashSet::new(),
            };
            // CNAME may point into a different domain, so restart from roots
            return resolve_step(&mut new_state, ROOT_SERVERS);
        }

        // Check for referral (NS records in authority section)
        let ns_records = find_authority_ns_records(&msg);
        if !ns_records.is_empty() {
            println!("DEBUG: Found {} NS records in authority (referral)", ns_records.len());
            for ns in &ns_records {
                println!("DEBUG:   NS: {}", ns);
            }
            
            // Look for NS server addresses in additional section
            let ns_ips = find_additional_ns_ips(&msg, &ns_records);
            if !ns_ips.is_empty() {
                println!("DEBUG: Found {} NS IPs in additional section", ns_ips.len());
                for ip in &ns_ips {
                    println!("DEBUG:   {}", ip);
                }
                
                let ns_refs: Vec<&str> = ns_ips.iter().map(|s| s.as_str()).collect();
                let mut new_state = QueryState {
                    domain: state.domain.clone(),
                    qtype: state.qtype,
                    depth: state.depth,
                    visited: HashSet::new(),
                };
                return resolve_step(&mut new_state, &ns_refs);
            }
            
            // If no IPs in additional section, resolve NS names one at a time and
            // try querying each as soon as it resolves (lazy resolution).
            println!("DEBUG: No NS IPs in additional section, trying NS names one at a time");
            for ns_name in &ns_records {
                println!("DEBUG: Trying to resolve NS: {}", ns_name);
                if let Ok(results) = resolve(ns_name, RecordType::A) {
                    for (ip, _) in results {
                        println!("DEBUG: Resolved NS {} -> {}, trying to query", ns_name, ip);
                        let mut new_state = QueryState {
                            domain: state.domain.clone(),
                            qtype: state.qtype,
                            depth: state.depth,
                            visited: HashSet::new(),
                        };
                        let servers: Vec<&str> = vec![&ip];
                        match resolve_step(&mut new_state, &servers) {
                            Ok(found) => {
                                println!("DEBUG: Got answer via {}", ip);
                                return Ok(found);
                            }
                            Err(e) => {
                                println!("DEBUG: Failed via {}: {}", ip, e);
                            }
                        }
                    }
                } else {
                    println!("DEBUG: Failed to resolve NS: {}", ns_name);
                }
            }
            // If none of the NS names worked, try next server
        } else {
            // No NS referral - check if this is an authoritative "no data" response
            if has_soa_for_domain(&msg, &state.domain) {
                return Err(format!("No {} records for {}", state.qtype, state.domain));
            }
            last_error = format!("No answer, no referral from {} for {}", server_str, state.domain);
            continue;
        }
    }

    Err(format!("Failed to resolve {}: {}", state.domain, last_error))
}

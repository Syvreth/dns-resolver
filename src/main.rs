//! Recursive DNS Resolver
//!
//! A from-scratch DNS resolver that communicates directly with the DNS hierarchy,
//! starting from the root servers.

mod packet;
mod transport;
mod resolver;

use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Usage: {} <domain> [A|AAAA]", args[0]);
        println!("  Examples:");
        println!("    {} www.google.com", args[0]);
        println!("    {} www.amazon.com AAAA", args[0]);
        println!("    {} api.github.com", args[0]);
        return;
    }

    let domain = &args[1];
    let record_type = match args.get(2) {
        Some(t) if t.to_uppercase() == "AAAA" => packet::RecordType::AAAA,
        Some(t) if t.to_uppercase() == "A" => packet::RecordType::A,
        Some(t) => {
            println!("Error: Unknown record type '{}'. Use 'A' or 'AAAA'.", t);
            return;
        }
        None => packet::RecordType::A,
    };

    println!("Resolving: {} ({:?})", domain, record_type);
    println!();

    match resolver::resolve_debug(domain, record_type) {
        Ok(results) => {
            println!("Results:");
            for (ip, cname) in &results {
                if let Some(cname) = cname {
                    println!("  CNAME: {} -> {}", ip, cname);
                } else {
                    println!("  {}", ip);
                }
            }
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }
}

//! Recursive DNS Resolver
//!
//! A from-scratch DNS resolver that communicates directly with the DNS hierarchy,
//! starting from the root servers.

// Declared first so its `debug!` macro is visible in the modules below.
#[macro_use]
mod log;
mod packet;
mod transport;
mod resolver;
mod cache;

use std::env;

fn is_verbose_flag(arg: &str) -> bool {
    arg == "-v" || arg == "--verbose"
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = &args[0];
    log::set_verbose(args[1..].iter().any(|a| is_verbose_flag(a)));
    // The flag may appear anywhere; everything else is <domain> [type].
    let positional: Vec<&String> = args[1..].iter().filter(|a| !is_verbose_flag(a)).collect();

    if positional.is_empty() {
        println!("Usage: {} [-v|--verbose] <domain> [A|AAAA]", program);
        println!("  -v, --verbose   show every query, referral and cache hit");
        println!("  Examples:");
        println!("    {} www.google.com", program);
        println!("    {} www.amazon.com AAAA", program);
        println!("    {} -v api.github.com", program);
        return;
    }

    let domain = positional[0];
    let record_type = match positional.get(1) {
        Some(t) if t.to_uppercase() == "AAAA" => packet::RecordType::AAAA,
        Some(t) if t.to_uppercase() == "A" => packet::RecordType::A,
        Some(t) => {
            println!("Error: Unknown record type '{}'. Use 'A' or 'AAAA'.", t);
            return;
        }
        None => packet::RecordType::A,
    };

    debug!("Resolving: {} ({:?})", domain, record_type);
    debug!();

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

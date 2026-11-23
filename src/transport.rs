//! DNS Network Transport
//!
//! Handles UDP and TCP socket communication with DNS servers.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::net::UdpSocket;
use std::time::Duration;

/// Send a DNS query via UDP and receive a response
pub fn send_query(server: &str, query: &[u8], timeout_ms: u64) -> Result<Vec<u8>, String> {
    let addr = format!("{}:53", server);
    let socket = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| format!("Failed to bind socket: {}", e))?;

    socket.set_read_timeout(Some(Duration::from_millis(timeout_ms)))
        .map_err(|e| format!("Failed to set timeout: {}", e))?;

    socket.connect(&addr)
        .map_err(|e| format!("Failed to connect to {}: {}", server, e))?;

    socket.send(query)
        .map_err(|e| format!("Failed to send query: {}", e))?;

    let mut response = vec![0u8; 4096];
    let bytes = socket.recv_from(&mut response)
        .map_err(|e| format!("Failed to receive response from {}: {}", server, e))?;

    response.truncate(bytes.0);
    Ok(response)
}

/// Send a DNS query via TCP and receive a response.
/// TCP DNS prepends a 2-byte length field to the query.
pub fn send_query_tcp(server: &str, query: &[u8], timeout_ms: u64) -> Result<Vec<u8>, String> {
    let addr = format!("{}:53", server);
    let mut stream = TcpStream::connect_timeout(
        &addr.parse().map_err(|e| format!("Failed to parse {}: {}", addr, e))?,
        Duration::from_millis(timeout_ms),
    ).map_err(|e| format!("Failed to connect to {}: {}", server, e))?;

    stream.set_read_timeout(Some(Duration::from_millis(timeout_ms)))
        .map_err(|e| format!("Failed to set timeout: {}", e))?;

    // TCP DNS: prepend 2-byte length
    let length_prefix = ((query.len() >> 8) & 0xFF) as u8;
    let length_prefix_low = (query.len() & 0xFF) as u8;
    stream.write_all(&[length_prefix, length_prefix_low])
        .map_err(|e| format!("Failed to send length prefix: {}", e))?;
    stream.write_all(query)
        .map_err(|e| format!("Failed to send query: {}", e))?;

    // Read length prefix of response
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf)
        .map_err(|e| format!("Failed to read response length: {}", e))?;
    let response_len = ((len_buf[0] as usize) << 8) | (len_buf[1] as usize);

    let mut response = vec![0u8; response_len];
    stream.read_exact(&mut response)
        .map_err(|e| format!("Failed to read response from {}: {}", server, e))?;

    Ok(response)
}

/// Send a query with retries
pub fn send_query_with_retries(server: &str, query: &[u8], timeout_ms: u64, retries: u32) -> Result<Vec<u8>, String> {
    let mut last_error = String::new();

    for attempt in 0..retries {
        match send_query(server, query, timeout_ms) {
            Ok(response) => return Ok(response),
            Err(e) => {
                last_error = e;
                if attempt < retries - 1 {
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }

    Err(format!("All {} attempts to {} failed: {}", retries, server, last_error))
}
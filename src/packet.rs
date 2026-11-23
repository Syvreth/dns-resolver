//! DNS Packet Encoding and Decoding
//!
//! DNS packet format:
//! - Header: 12 bytes
///   - Transaction ID (2 bytes)
///   - Flags (2 bytes): QR, OPCODE, AA, TC, RD, RA, RCODE
///   - Question Count (2 bytes)
///   - Answer Count (2 bytes)
///   - Authority Count (2 bytes)
///   - Additional Count (2 bytes)
/// - Questions: variable length
///   - QNAME: length-prefixed labels terminated by 0-length label
///   - QTYPE (2 bytes)
///   - QCLASS (2 bytes)
/// - Answers: variable length (same format as question + RR fields)
/// - Authority: variable length
/// - Additional: variable length
///
/// Domain Name Compression:
/// - Names start with 0xC0 followed by 1 byte offset
/// - Offset is relative to start of packet
/// - Used in responses to reduce size
/// - Can be chained



/// DNS record types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum RecordType {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    AAAA = 28,
    OPT = 41,
    Unknown(u16),
}

impl RecordType {
    pub fn from_u16(t: u16) -> RecordType {
        match t {
            1 => RecordType::A,
            2 => RecordType::NS,
            5 => RecordType::CNAME,
            6 => RecordType::SOA,
            28 => RecordType::AAAA,
            41 => RecordType::OPT,
            _ => RecordType::Unknown(t),
        }
    }

    pub fn to_u16(&self) -> u16 {
        match self {
            RecordType::A => 1,
            RecordType::NS => 2,
            RecordType::CNAME => 5,
            RecordType::SOA => 6,
            RecordType::AAAA => 28,
            RecordType::OPT => 41,
            RecordType::Unknown(t) => *t,
        }
    }
}

impl std::fmt::Display for RecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            RecordType::A => write!(f, "A"),
            RecordType::NS => write!(f, "NS"),
            RecordType::CNAME => write!(f, "CNAME"),
            RecordType::SOA => write!(f, "SOA"),
            RecordType::AAAA => write!(f, "AAAA"),
            RecordType::OPT => write!(f, "OPT"),
            RecordType::Unknown(t) => write!(f, "TYPE{}", t),
        }
    }
}

/// DNS response codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rcode {
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3, // NXDOMAIN
    NotImplemented = 4,
}

impl Rcode {
    pub fn from_u8(c: u8) -> Rcode {
        match c {
            0 => Rcode::NoError,
            1 => Rcode::FormatError,
            2 => Rcode::ServerFailure,
            3 => Rcode::NameError,
            4 => Rcode::NotImplemented,
            _ => Rcode::FormatError,
        }
    }
}

/// DNS header
#[allow(dead_code)] // Fields opcode, aa, rd, ra reserved for upcoming features
#[derive(Debug, Clone)]
pub struct Header {
    pub id: u16,
    pub qr: bool,      // 0=query, 1=response
    pub opcode: u8,
    pub aa: bool,      // Authoritative Answer
    pub tc: bool,      // Truncated
    pub rd: bool,      // Recursion Desired
    pub ra: bool,      // Recursion Available
    pub rcode: Rcode,
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
}

/// A DNS question
#[allow(dead_code)] // Fields name, qtype, qclass reserved for upcoming features
#[derive(Debug, Clone)]
pub struct Question {
    pub name: String,
    pub qtype: RecordType,
    pub qclass: u16,
}

/// A DNS resource record (answer, authority, additional)
#[allow(dead_code)] // Fields rclass, ttl reserved for upcoming features
#[derive(Debug, Clone)]
pub struct Record {
    pub name: String,
    pub rtype: RecordType,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
    pub target: Option<String>, // Decoded NS/CNAME target
}

impl Record {
    /// Get the domain name from NS/CNAME record rdata (decoded at parse time)
    pub fn get_domain(&self) -> Option<String> {
        self.target.clone()
    }

    /// Get the IP address from A record rdata
    pub fn get_ip(&self) -> Option<String> {
        if self.rtype != RecordType::A || self.rdata.len() != 4 {
            return None;
        }
        Some(format!(
            "{}.{}.{}.{}",
            self.rdata[0], self.rdata[1], self.rdata[2], self.rdata[3]
        ))
    }

    /// Get the IP address from AAAA record rdata
    pub fn get_ip6(&self) -> Option<String> {
        if self.rtype != RecordType::AAAA || self.rdata.len() != 16 {
            return None;
        }
        let mut parts = Vec::new();
        for i in 0..8 {
            parts.push(format!("{:04x}", u16::from_be_bytes([self.rdata[i*2], self.rdata[i*2+1]])));
        }
        Some(parts.join(":"))
    }
}

/// A complete DNS message
#[allow(dead_code)] // Field questions reserved for upcoming features
#[derive(Debug, Clone)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub additional: Vec<Record>,
}

/// Encode a domain name to wire format
pub fn encode_name(name: &str) -> Vec<u8> {
    let mut result = Vec::new();
    for label in name.split('.') {
        result.push(label.len() as u8);
        result.extend_from_slice(label.as_bytes());
    }
    result.push(0); // Terminate with null byte
    result
}

/// Decode a domain name from wire format, handling compression pointers
fn decode_name_bytes(data: &[u8], offset: usize) -> String {
    if offset >= data.len() {
        return String::new();
    }

    let mut result = String::new();
    let mut pos = offset;
    let mut jumped = false;
    let mut visited = 0;

    while pos < data.len() {
        let label_len = data[pos] as usize;

        if label_len == 0 {
            break;
        } else if label_len & 0xC0 == 0xC0 {
            // Compression pointer
            if pos + 1 >= data.len() {
                break;
            }
            let ptr = ((data[pos] & 0x3F) as usize) << 8 | data[pos + 1] as usize;
            if !jumped {
                jumped = true;
            }
            pos = ptr;
            visited += 1;
            if visited > 100 {
                break; // Prevent infinite loops
            }
        } else {
            // Regular label
            if pos + 1 + label_len >= data.len() {
                break;
            }
            if !result.is_empty() {
                result.push('.');
            }
            result.push_str(
                std::str::from_utf8(&data[pos + 1..pos + 1 + label_len]).unwrap_or(""),
            );
            pos += 1 + label_len;
        }
    }

    result
}

/// Parse the header from a DNS message
fn parse_header(data: &[u8]) -> Result<Header, String> {
    if data.len() < 12 {
        return Err("Header too short".to_string());
    }

    let id = u16::from_be_bytes([data[0], data[1]]);
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let question_count = u16::from_be_bytes([data[4], data[5]]);
    let answer_count = u16::from_be_bytes([data[6], data[7]]);
    let authority_count = u16::from_be_bytes([data[8], data[9]]);
    let additional_count = u16::from_be_bytes([data[10], data[11]]);

    Ok(Header {
        id,
        qr: (flags & 0x8000) != 0,
        opcode: ((flags >> 11) & 0x0F) as u8,
        aa: (flags & 0x0400) != 0,
        tc: (flags & 0x0200) != 0,
        rd: (flags & 0x0100) != 0,
        ra: (flags & 0x0080) != 0,
        rcode: Rcode::from_u8((flags & 0x000F) as u8),
        question_count,
        answer_count,
        authority_count,
        additional_count,
    })
}

/// Parse questions from a DNS message
fn parse_questions(data: &[u8], count: u16, offset: usize) -> Result<(Vec<Question>, usize), String> {
    let mut questions = Vec::new();
    let mut pos = offset;

    for _ in 0..count {
        if pos >= data.len() {
            return Err("Question section truncated".to_string());
        }

        let name = decode_name_bytes(data, pos);
        // Find the end of the name
        let mut temp_pos = pos;
        loop {
            if temp_pos >= data.len() {
                break;
            }
            let byte = data[temp_pos];
            if byte == 0 {
                temp_pos += 1;
                break;
            } else if byte & 0xC0 == 0xC0 {
                temp_pos += 2;
                break;
            } else {
                temp_pos += 1 + byte as usize;
            }
        }
        pos = temp_pos;

        if pos + 4 > data.len() {
            return Err("Question type/class truncated".to_string());
        }

        let qtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let qclass = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
        pos += 4;

        let record_type = RecordType::from_u16(qtype);
        questions.push(Question {
            name,
            qtype: record_type,
            qclass,
        });
    }

    Ok((questions, pos))
}

/// Parse a single resource record
fn parse_record(data: &[u8], offset: usize) -> Result<(Record, usize), String> {
    let mut pos = offset;

    if pos >= data.len() {
        return Err("Record name truncated".to_string());
    }

    let name = decode_name_bytes(data, pos);
    // Find the end of the name
    let mut temp_pos = pos;
    loop {
        if temp_pos >= data.len() {
            break;
        }
        let byte = data[temp_pos];
        if byte == 0 {
            temp_pos += 1;
            break;
        } else if byte & 0xC0 == 0xC0 {
            temp_pos += 2;
            break;
        } else {
            temp_pos += 1 + byte as usize;
        }
    }
    pos = temp_pos;

    if pos + 10 > data.len() {
        return Err("Record header truncated".to_string());
    }

    let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
    let rclass = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
    let ttl = u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
    let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
    pos += 10;

    if pos + rdlength > data.len() {
        return Err("Record data truncated".to_string());
    }

    let rdata = data[pos..pos + rdlength].to_vec();
    pos += rdlength;

    let record_type = RecordType::from_u16(rtype);

    // Decode NS/CNAME target at parse time, using full packet for compression pointers
    let target = match record_type {
        RecordType::NS | RecordType::CNAME => {
            if rdlength > 0 && pos - rdlength < data.len() {
                let name = decode_name_bytes(data, pos - rdlength);
                if !name.is_empty() {
                    Some(name)
                } else {
                    None
                }
            } else {
                None
            }
        }
        _ => None,
    };

    let record = Record {
        name,
        rtype: record_type,
        rclass,
        ttl,
        rdata,
        target,
    };

    Ok((record, pos))
}

/// Parse multiple resource records
fn parse_records(data: &[u8], count: u16, offset: usize) -> Result<(Vec<Record>, usize), String> {
    let mut records = Vec::new();
    let mut pos = offset;

    for _ in 0..count {
        let (record, new_pos) = parse_record(data, pos)?;
        records.push(record);
        pos = new_pos;
    }

    Ok((records, pos))
}

/// Parse a complete DNS message from bytes
pub fn parse_message(data: &[u8]) -> Result<Message, String> {
    let header = parse_header(data)?;
    let (questions, qpos) = parse_questions(data, header.question_count, 12)?;
    let (answers, apos) = parse_records(data, header.answer_count, qpos)?;
    let (authority, upos) = parse_records(data, header.authority_count, apos)?;
    let (additional, _) = parse_records(data, header.additional_count, upos)?;

    Ok(Message {
        header,
        questions,
        answers,
        authority,
        additional,
    })
}

/// Build a DNS query packet
/// If edns0_payload_size is set, includes an EDNS0 OPT record advertising
/// that we can accept that many bytes in UDP responses.
pub fn build_query(id: u16, domain: &str, qtype: RecordType, edns0_payload_size: Option<u16>) -> Vec<u8> {
    let mut packet = Vec::new();

    // Header
    packet.extend_from_slice(&id.to_be_bytes());
    let flags: u16 = 0x0000; // No RD bit (iterative resolution)
    packet.extend_from_slice(&flags.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes()); // Question count
    packet.extend_from_slice(&0u16.to_be_bytes()); // Answer count
    packet.extend_from_slice(&0u16.to_be_bytes()); // Authority count

    // EDNS0 OPT record counts as 1 additional record
    let edns0_count = match edns0_payload_size {
        Some(_) => 1u16,
        None => 0u16,
    };
    packet.extend_from_slice(&edns0_count.to_be_bytes()); // Additional count

    // Question
    let name_bytes = encode_name(domain);
    packet.extend_from_slice(&name_bytes);
    packet.extend_from_slice(&qtype.to_u16().to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes()); // IN class

    // EDNS0 OPT record (if requested)
    // Name: root (empty label)
    // Type: 41 (OPT)
    // Class: UDP payload size we can accept
    // TTL: 0 (no extended RCODE or version)
    // Rdata: empty (no options)
    if let Some(payload_size) = edns0_payload_size {
        packet.push(0); // Root name
        packet.extend_from_slice(&41u16.to_be_bytes()); // Type OPT
        packet.extend_from_slice(&payload_size.to_be_bytes()); // UDP payload size
        packet.extend_from_slice(&0u32.to_be_bytes()); // TTL (extended RCODE/version)
        packet.extend_from_slice(&0u16.to_be_bytes()); // Rdata length
    }

    packet
}

/// Find A/AAAA records for a domain in the answer section.
/// Does not return CNAMEs (caller should follow those separately).
pub fn find_ip_records(msg: &Message, domain: &str) -> Vec<(String, Option<String>)> {
    let mut results = Vec::new();

    for record in &msg.answers {
        if record.name.to_lowercase() == domain.to_lowercase() {
            if record.rtype == RecordType::A {
                if let Some(ip) = record.get_ip() {
                    results.push((ip, None));
                }
            } else if record.rtype == RecordType::AAAA {
                if let Some(ip6) = record.get_ip6() {
                    results.push((ip6, None));
                }
            }
        }
    }

    results
}

/// Check if the message contains an SOA record in the
/// authority section (indicating an authoritative "no data" response).
pub fn has_soa_for_domain(msg: &Message, _domain: &str) -> bool {
    for record in &msg.authority {
        if record.rtype == RecordType::SOA {
            return true;
        }
    }
    false
}

/// Find CNAME records for a domain in the answer section
pub fn find_cname_records(msg: &Message, domain: &str) -> Vec<String> {
    let mut targets = Vec::new();
    for record in &msg.answers {
        if record.name.to_lowercase() == domain.to_lowercase() && record.rtype == RecordType::CNAME {
            if let Some(target) = record.get_domain() {
                targets.push(target);
            }
        }
    }
    targets
}

/// The zone a referral delegates to (the owner name of the NS records in the authority
/// section, e.g. "com") and the shortest TTL among those NS records.
pub fn find_referral_zone(msg: &Message) -> Option<(String, u32)> {
    let mut zone: Option<(String, u32)> = None;
    for record in msg.authority.iter().filter(|r| r.rtype == RecordType::NS) {
        match &mut zone {
            None => zone = Some((record.name.clone(), record.ttl)),
            Some((name, ttl)) if name.eq_ignore_ascii_case(&record.name) => *ttl = (*ttl).min(record.ttl),
            Some(_) => {}
        }
    }
    zone
}

/// Find all NS records in the authority section (for referrals)
pub fn find_authority_ns_records(msg: &Message) -> Vec<String> {
    let mut ns_names = Vec::new();
    for record in &msg.authority {
        if record.rtype == RecordType::NS {
            if let Some(ns_name) = record.get_domain() {
                if !ns_names.contains(&ns_name) {
                    ns_names.push(ns_name);
                }
            }
        }
    }
    ns_names
}

/// Find IP addresses for NS servers in the additional section
pub fn find_additional_ns_ips(msg: &Message, ns_names: &[String]) -> Vec<String> {
    let mut ips = Vec::new();
    for record in &msg.additional {
        for ns_name in ns_names {
            if record.name.to_lowercase() == ns_name.to_lowercase() {
                if record.rtype == RecordType::A {
                    if let Some(ip) = record.get_ip() {
                        if !ips.contains(&ip) {
                            ips.push(ip);
                        }
                    }
                }
            }
        }
    }
    ips
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(owner: &str, rtype: RecordType, ttl: u32) -> Record {
        Record { name: owner.into(), rtype, rclass: 1, ttl, rdata: Vec::new(), target: None }
    }

    fn with_authority(authority: Vec<Record>) -> Message {
        Message {
            header: Header {
                id: 0, qr: true, opcode: 0, aa: false, tc: false, rd: false, ra: false,
                rcode: Rcode::NoError, question_count: 0, answer_count: 0,
                authority_count: authority.len() as u16, additional_count: 0,
            },
            questions: Vec::new(),
            answers: Vec::new(),
            authority,
            additional: Vec::new(),
        }
    }

    #[test]
    fn referral_zone_is_the_ns_owner_with_the_shortest_ttl() {
        let msg = with_authority(vec![
            record("amazon.com", RecordType::NS, 172800),
            record("Amazon.com", RecordType::NS, 3600),
            record("amazon.com", RecordType::NS, 86400),
        ]);
        assert_eq!(find_referral_zone(&msg), Some(("amazon.com".into(), 3600)));
    }

    #[test]
    fn no_ns_records_means_no_referral_zone() {
        let msg = with_authority(vec![record("amazon.com", RecordType::SOA, 900)]);
        assert_eq!(find_referral_zone(&msg), None);
    }
}

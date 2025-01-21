use std::env;
use std::net::UdpSocket;

pub struct DnsRecord {
    domain: String,
    record_a: Vec<String>,
    record_mx: Vec<(u16, String)>
}

impl DnsRecord {
    pub fn new(domain: String) -> Self {
        Self {
            domain,
            record_a: Vec::new(),
            record_mx: Vec::new()
        }
    }

    pub fn create_dns_query(&self, query_type: u8) -> Vec<u8> {
        let mut query = Vec::new();
        query.extend(&[0x12, 0x34]);     // ID
        query.extend(&[0x01, 0x00]);     // Flags
        query.extend(&[0x00, 0x01]);     // Questions
        query.extend(&[0x00, 0x00]);     // Answers
        query.extend(&[0x00, 0x00]);     // Authority
        query.extend(&[0x00, 0x00]);     // Additional
        
        // Encoder le nom de domaine
        let encoded_domain = self.encode_domain();
        query.extend(encoded_domain);
        
        query.extend(&[0x00, query_type]);  // Type (A ou MX)
        query.extend(&[0x00, 0x01]);     // Class IN
        query
    }

    fn encode_domain(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        for part in self.domain.split('.') {
            encoded.push(part.len() as u8);
            encoded.extend(part.as_bytes());
        }
        encoded.push(0);
        encoded
    }

    pub fn parse_ip(&mut self, response: &[u8]) {
        if response.len() < 12 { return; }

        let mut pos = 12;
        // Sauter la question
        while pos < response.len() && response[pos] != 0 {
            pos += 1 + response[pos] as usize;
        }
        pos += 5;
        
        if pos + 12 >= response.len() { return; }
        pos += 10;
        pos += 2;
        
        if pos + 4 > response.len() { return; }
        
        self.record_a.push(format!("{}.{}.{}.{}", 
            response[pos],
            response[pos + 1],
            response[pos + 2],
            response[pos + 3]
        ));
    }

    pub fn parse_mx_records(response: &[u8]) -> Vec<(u16, String)> {
        let mut records = Vec::new();
        let answers = response[7] as usize;
        
        if response.len() < 12 { return records; }
    
        let mut pos = 12;
        // Sauter la question
        while pos < response.len() && response[pos] != 0 {
            pos += 1 + response[pos] as usize;
        }
        pos += 5;
    
        for _ in 0..answers {
            if pos + 10 >= response.len() { break; }
    
            // Sauter le nom compressé
            if (response[pos] & 0xC0) == 0xC0 {
                pos += 2;
            } else {
                while pos < response.len() && response[pos] != 0 {
                    pos += 1 + response[pos] as usize;
                }
                pos += 1;
            }
    
            pos += 8; // Type + Class + TTL
            let data_len = ((response[pos] as usize) << 8) | response[pos + 1] as usize;
            pos += 2;
    
            if pos + data_len > response.len() { break; }
    
            let priority = ((response[pos] as u16) << 8) | response[pos + 1] as u16;
            pos += 2;
    
            let (mx_server, new_pos) = Self::decode_name(response, pos);
            pos = new_pos;
    
            records.push((priority, mx_server));
        }
    
        records
    }

    fn decode_name(response: &[u8], start_pos: usize) -> (String, usize) {
        let mut pos = start_pos;
        let mut name = String::new();
    
        loop {
            let length = response[pos] as usize;
            
            if (length & 0xC0) == 0xC0 {
                let offset = ((length & 0x3F) as usize) << 8 | response[pos + 1] as usize;
                let (compressed_name, _) = Self::decode_name(response, offset);
                if !name.is_empty() {
                    name.push('.');
                }
                name.push_str(&compressed_name);
                return (name, pos + 2);
            }
    
            if length == 0 { break; }
    
            pos += 1;
            if !name.is_empty() {
                name.push('.');
            }
            name.push_str(std::str::from_utf8(&response[pos..pos + length]).unwrap_or("invalid"));
            pos += length;
        }
    
        (name, pos + 1)
    }

    pub fn get_mx_records(&mut self) -> Vec<(u16, String)> {
        self.record_mx.clone()
    }

    pub fn get_a_records(&self) -> Vec<String> {
        self.record_a.clone()
    }
}


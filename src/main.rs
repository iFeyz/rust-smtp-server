use tokio::net::{TcpListener, TcpStream};
use tokio::io::{
    AsyncWriteExt, AsyncBufReadExt, BufReader, BufWriter,
    AsyncRead,
};
use std::net::SocketAddr;
use tokio_util::codec::{Framed, LinesCodec};
use futures::{stream::iter, SinkExt, StreamExt};
use native_tls::{Identity, TlsAcceptor};
use tokio_native_tls::{TlsAcceptor as TokioTlsAcceptor, TlsStream};
use trust_dns_resolver::{
    config::{ResolverConfig , ResolverOpts},
    AsyncResolver,
    proto::rr::{RData , RecordType}
};

use openssl::{

    asn1::Asn1Time,
    pkey::PKey,
    rsa::Rsa,
    x509::{
        extension::{AuthorityKeyIdentifier, BasicConstraints, SubjectKeyIdentifier},
        X509NameBuilder, X509,
    },
};


// Définition de l'enum SmtpState
#[derive(Debug)]
enum SmtpState {
    Command,
    Data,
    Quit,
}

#[derive(Debug , Clone)]
struct Email {
    sender : String,
    receiver : String,
    subject : String,
    data : String
}

impl Email {
    fn new() -> Self {
        Self {
            sender : String::new(),
            receiver : String::new(),
            subject : String::new(),
            data : String::new()
        }
    }
}

async fn listen() -> anyhow::Result<()> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 2525));
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("Listening on {}", addr);
    
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(async move {
                    if let Err(err) = handle_connection(stream).await {
                        tracing::error!("Error handling SMTP connection: {:?}", err);
                    }
                });
            }
            Err(err) => {
                tracing::error!("Error accepting connection: {:?}", err);
            }
        }
    }
}

async fn handle_connection(stream: TcpStream) -> anyhow::Result<()> {
    let std_stream = stream.into_std()?;
    let cloned_stream = std_stream.try_clone()?;
    
    let stream_for_tls = TcpStream::from_std(cloned_stream)?;
    let stream = TcpStream::from_std(std_stream)?;
    
    let (read_half, write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut writer = BufWriter::new(write_half);
    writer.write_all(b"220 smtp-server ready\r\n").await?;
    writer.flush().await?;
    
    handle_unsecured_session(&mut reader, &mut writer, stream_for_tls).await
}

async fn handle_session(stream: TlsStream<TcpStream>) -> anyhow::Result<()> {
    let RE_SMTP_MAIL = regex::Regex::new(r"(?i)from: ?<(.+)>").unwrap();
    let RE_SMTP_RCPT = regex::Regex::new(r"(?i)to: ?<(.+)>").unwrap();
    let mut message = String::new();
    let mut state = SmtpState::Command;
    let mut mailfrom: Option<String> = None;
    let mut rcpts: Vec<String> = Vec::new();
    let mut framed = Framed::new(stream, LinesCodec::new());

    while let Some(line_result) = framed.next().await {
        let line = line_result?;
        match state {
            SmtpState::Command => {
                let space_pos = line.find(" ").unwrap_or(line.len());
                let (command, arg) = line.split_at(space_pos);
                let arg = arg.trim();
                match &*command.trim().to_uppercase() {
                    "HELO" | "EHLO" => {
                        send_commands(&mut framed, vec!["250 Hello".to_string()]).await?;
                    }
                    "MAIL" => {
                        if let Some(address) = RE_SMTP_MAIL.captures(arg).and_then(|cap| cap.get(1)) {
                            mailfrom = Some(address.as_str().to_string());
    
                            send_commands(&mut framed, vec!["250 OK".to_string()]).await?;
                        } else {
                            send_commands(&mut framed, vec!["501 Syntax: MAIL From: <address>".to_string()]).await?;
                        }
                    }
                    "RCPT" => {
                        if mailfrom.is_none() {
                            send_commands(&mut framed, vec!["503 Error: Send MAIL first".to_string()]).await?;
                        } else {
                            if let Some(address) = RE_SMTP_RCPT.captures(arg).and_then(|cap| cap.get(1)) {
                                rcpts.push(address.as_str().to_string());
                                send_commands(&mut framed, vec!["250 OK".to_string()]).await?;
                            } else {
                                send_commands(&mut framed, vec!["501 Syntax: RCPT TO: <address>".to_string()]).await?;
                            }
                        }
                    }
                    "DATA" => {
                        if rcpts.is_empty() {
                            send_commands(&mut framed, vec![String::from("503 Error: MAIL FROM and RCPT TO must be set before sending DATA")]).await?;
                        } else {
                            state = SmtpState::Data;
                        
                            send_commands(&mut framed, vec!["354 End data with <CR><LF>.<CR><LF>".to_string()]).await?;
                        }
                    }
                    "NOOP" => {
                        send_commands(&mut framed, vec!["250 OK".to_string()]).await?;
                    }
                    "RSET" => {
                        mailfrom = None;
                        rcpts = Vec::new();
                        message = String::new();
                        send_commands(&mut framed, vec!["250 OK".to_string()]).await?;
                    }
                    "QUIT" => {
                        send_commands(&mut framed, vec!["221 Bye".to_string()]).await?;
                        state = SmtpState::Quit;
                    }
                    _ => {
                        send_commands(&mut framed, vec!["500 Unknown command".to_string()]).await?;
                    }
                }
            }
            SmtpState::Data => {
                if line.trim() == "." {
                    send_commands(&mut framed, vec!["250 OK".to_string()]).await?;
                    handle_email(mailfrom.clone(), rcpts.clone(), message.clone()).await?;
                    mailfrom = None;
                    rcpts = Vec::new();
                    message = String::new();
                    state = SmtpState::Command;
                } else {
                    message.push_str(&line);
                    message.push_str("\n");
                }
            }
            SmtpState::Quit => break,
        }
    }
    Ok(())
}

async fn handle_email(from: Option<String>, to: Vec<String>, content: String) -> anyhow::Result<()> {
    let mut email = Email::new();
    email.sender = from.ok_or_else(|| anyhow::anyhow!("From address is required"))?;
    
    for recipient in to {
        email.receiver = recipient;
        
        // Parser le contenu du mail
        let (subject, body) = parse_email_content(&content)
            .ok_or_else(|| anyhow::anyhow!("Failed to parse email content"))?;
        
        email.subject = subject;
        email.data = body;
        
        tracing::debug!("Sending email: \nFrom: {}\nTo: {}\nSubject: {}\nBody length: {}",
            email.sender, email.receiver, email.subject, email.data.len());
        
        if let Err(e) = send_mail_not_in_domain(&email).await {
            tracing::error!("Failed to send email to {}: {}", email.receiver, e);
        }
    }
    
    Ok(())
}

fn parse_email_content(content: &str) -> Option<(String, String)> {
    let mut lines = content.lines();
    let mut subject = String::new();
    let mut body = Vec::new();
    let mut in_headers = true;
    let mut found_subject = false;
    
    // Parcourir les lignes pour trouver les en-têtes et le corps
    while let Some(line) = lines.next() {
        if in_headers {
            // Une ligne vide marque la fin des en-têtes
            if line.trim().is_empty() {
                in_headers = false;
                continue;
            }
            
            // Chercher l'en-tête Subject
            if line.to_lowercase().starts_with("subject:") {
                subject = line["subject:".len()..].trim().to_string();
                found_subject = true;
            }
        } else {
            // Tout ce qui suit la ligne vide est le corps du message
            body.push(line);
        }
    }
    
    // Si aucun sujet n'a été trouvé, utiliser un sujet par défaut
    if !found_subject {
        subject = "(No subject)".to_string();
    }
    
    // Joindre les lignes du corps avec des retours à la ligne
    let body = body.join("\r\n");
    
    Some((subject, body))
}

async fn send_commands(framed: &mut Framed<TlsStream<TcpStream>, LinesCodec>, commands: Vec<String>) -> anyhow::Result<()> {
    let messages = iter(commands.into_iter().map(|x| format!("{}\r", x)));
    framed.send_all(&mut messages.map(Ok)).await?;
    Ok(())
}

async fn handle_unsecured_session(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    writer: &mut BufWriter<tokio::net::tcp::OwnedWriteHalf>,
    stream_for_tls: TcpStream,
) -> anyhow::Result<()> {
    let mut is_tls = false;
    let mut line = String::new();
    
    // Ajouter un flag pour suivre si STARTTLS est requis
    let mut starttls_required = false;

    while reader.read_line(&mut line).await? != 0 {
        let trimmed_line = line.trim_end_matches(|c| c == '\r' || c == '\n');
        tracing::debug!("Received command: {}", trimmed_line);
        
        let parts: Vec<&str> = trimmed_line.splitn(2, ' ').collect();
        let command = parts[0].trim().to_uppercase();
        let args = parts.get(1).map(|s| s.trim()).unwrap_or("");

        match command.as_str() {
            "EHLO" | "HELO" => {
                tracing::debug!("Handling EHLO/HELO command with args: {}", args);
                writer.write_all(b"250-windmill Hello\r\n").await?;
                writer.write_all(b"250-STARTTLS\r\n").await?;
                writer.write_all(b"250 STARTTLS required\r\n").await?;
                writer.flush().await?;
                starttls_required = true;
            }
            "STARTTLS" => {
                if starttls_required {
                    writer.write_all(b"220 Ready to start TLS\r\n").await?;
                    writer.flush().await?;
                    is_tls = true;
                    break;
                } else {
                    writer.write_all(b"503 EHLO/HELO first\r\n").await?;
                    writer.flush().await?;
                }
            }
            "QUIT" => {
                writer.write_all(b"221 Have a nice day!\r\n").await?;
                writer.flush().await?;
                break;
            }
            "NOOP" => {
                writer.write_all(b"250 OK\r\n").await?;
                writer.flush().await?;
            }
            "MAIL" | "RCPT" | "DATA" | "RSET" => {
                if !starttls_required {
                    writer.write_all(b"503 EHLO/HELO first\r\n").await?;
                } else {
                    writer.write_all(b"530 Must issue a STARTTLS command first\r\n").await?;
                }
                writer.flush().await?;
            }
            _ => {
                tracing::warn!("Unknown command received: {}", command);
                writer.write_all(b"500 Unknown command\r\n").await?;
                writer.flush().await?;
            }
        }
        line.clear();
    }

    if is_tls {
        handle_starttls(stream_for_tls).await?;
    }
    Ok(())
}

async fn handle_starttls(stream: TcpStream) -> anyhow::Result<()> {
    let (pem_certificate, pem_private_key) = generate_certificate()?;
    let identity = Identity::from_pkcs8(pem_certificate.as_bytes(), pem_private_key.as_bytes())?;
    
    let tls_acceptor = TlsAcceptor::builder(identity)
        .min_protocol_version(Some(native_tls::Protocol::Tlsv12))
        .build()?;
    let tls_acceptor = TokioTlsAcceptor::from(tls_acceptor);
    
    tracing::debug!("Starting TLS handshake");
    match tls_acceptor.accept(stream).await {
        Ok(tls_stream) => {
            tracing::debug!("TLS handshake successful");
            handle_session(tls_stream).await
        }
        Err(e) => {
            tracing::error!("TLS handshake failed: {:?}", e);
            Err(anyhow::anyhow!("TLS handshake failed: {}", e))
        }
    }
}

fn generate_certificate() -> anyhow::Result<(String, String)> {
    let cert_result = {
        let rsa = Rsa::generate(4096)?;
        let pkey = PKey::from_rsa(rsa)?;
        let mut name = X509NameBuilder::new()?;
        name.append_entry_by_text("CN", "localhost")?;
        let name = name.build();
        let mut builder = X509::builder()?;
        builder.set_version(2)?;
        builder.set_subject_name(&name)?;
        builder.set_issuer_name(&name)?;
        builder.set_pubkey(&pkey)?;
        let now = Asn1Time::days_from_now(0)?;
        let later = Asn1Time::days_from_now(3650)?;
        builder.set_not_before(now.as_ref())?;
        builder.set_not_after(later.as_ref())?;
        builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
        builder.append_extension(SubjectKeyIdentifier::new().build(&builder.x509v3_context(None, None))?)?;
        builder.append_extension(AuthorityKeyIdentifier::new().keyid(true).issuer(true).build(&builder.x509v3_context(None, None))?)?;
        builder.sign(&pkey, openssl::hash::MessageDigest::sha256())?;
        let cert = builder.build();
        Ok((
            String::from_utf8(cert.to_pem()?)?,
            String::from_utf8(pkey.private_key_to_pem_pkcs8()?)?
        ))
    };

    cert_result.map_err(|e: openssl::error::ErrorStack| anyhow::anyhow!("Could not generate self-signed certificates: {}", e))
}

async fn get_mx_records(domain: &str) -> anyhow::Result<Vec<(u16, String)>> {
    let resolver = AsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())?;
    let response = resolver.lookup(domain, RecordType::MX).await?;
    
    let mut mx_records = Vec::new();
    for record in response.iter() {
        if let RData::MX(mx) = record {
            mx_records.push((mx.preference(), mx.exchange().to_string()));
        }
    }
    
    // Trier par préférence (plus petit = plus prioritaire)
    mx_records.sort_by_key(|(pref, _)| *pref);
    Ok(mx_records)
}

async fn get_a_records(server: &str) -> anyhow::Result<Vec<std::net::IpAddr>> {
    let resolver = AsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())?;
    let response = resolver.lookup_ip(server).await?;
    Ok(response.iter().collect())
}

async fn send_mail_not_in_domain(email: &Email) -> anyhow::Result<()> {
    tracing::info!("Starting email forwarding process");
    
    // Extraire le domaine du destinataire
    let domain = email.receiver.split('@').nth(1)
        .ok_or_else(|| anyhow::anyhow!("Invalid recipient address"))?;
    
    // Configuration spéciale pour Gmail
    if domain == "gmail.com" {
        tracing::info!("Gmail detected, using Gmail SMTP servers");
        let gmail_servers = vec![
            "smtp.gmail.com:587",
            "alt1.gmail-smtp-in.l.google.com:587",
            "alt2.gmail-smtp-in.l.google.com:587",
            "alt3.gmail-smtp-in.l.google.com:587",
            "alt4.gmail-smtp-in.l.google.com:587",
        ];
        
        for server in gmail_servers {
            match TcpStream::connect(server).await {
                Ok(stream) => {
                    tracing::info!("Connected to Gmail SMTP server: {}", server);
                    match send_smtp_mail_tls(stream, email).await {
                        Ok(_) => {
                            tracing::info!("Successfully forwarded email to {} via {}", email.receiver, server);
                            return Ok(());
                        }
                        Err(e) => {
                            tracing::error!("Failed to send email through {}: {}", server, e);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to connect to Gmail server {}: {}", server, e);
                }
            }
        }
        return Err(anyhow::anyhow!("Failed to send email to Gmail after trying all servers"));
    }
    
    // Pour les autres domaines, continuer avec la logique existante...
    tracing::debug!("Resolving MX records for domain: {}", domain);
    
    // Obtenir les enregistrements MX
    let mx_records = get_mx_records(domain).await?;
    if mx_records.is_empty() {
        tracing::error!("No MX records found for domain {}", domain);
        return Err(anyhow::anyhow!("No MX records found for domain {}", domain));
    }
    tracing::debug!("Found {} MX records", mx_records.len());
    
    // Essayer chaque serveur MX dans l'ordre de préférence
    for (pref, mx_server) in mx_records {
        tracing::debug!("Trying MX server {} (preference {})", mx_server, pref);
        
        // Obtenir les adresses IP du serveur MX
        match get_a_records(&mx_server).await {
            Ok(ips) => {
                tracing::debug!("Resolved {} to {} IP addresses", mx_server, ips.len());
                for ip in ips {
                    tracing::debug!("Attempting connection to SMTP server at {}:25", ip);
                    // Tenter de se connecter au serveur SMTP
                    match TcpStream::connect((ip, 25)).await {
                        Ok(stream) => {
                            tracing::info!("Connected to SMTP server at {}:25", ip);
                            match send_smtp_mail(stream, email).await {
                                Ok(_) => {
                                    tracing::info!("Successfully forwarded email to {} via {}", email.receiver, ip);
                                    return Ok(());
                                }
                                Err(e) => {
                                    tracing::error!("Failed to send email through {}: {}", ip, e);
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Failed to connect to {}: {}", ip, e);
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to resolve {}: {}", mx_server, e);
                continue;
            }
        }
    }
    
    tracing::error!("Failed to send email to {} after trying all MX servers", email.receiver);
    Err(anyhow::anyhow!("Failed to send email to any MX server"))
}

async fn read_smtp_response(reader: &mut BufReader<impl AsyncRead + Unpin>) -> anyhow::Result<Vec<String>> {
    let mut responses = Vec::new();
    let mut line = String::new();
    
    loop {
        line.clear();
        reader.read_line(&mut line).await?;
        let trimmed = line.trim().to_string();
        tracing::debug!("Received SMTP response: {}", trimmed);
        
        responses.push(trimmed.clone());
        
        // Si la ligne commence par "250 " (sans tiret), c'est la dernière
        if trimmed.starts_with("250 ") {
            break;
        }
        // Si ce n'est pas une continuation (250-), c'est une erreur
        if !trimmed.starts_with("250-") {
            return Err(anyhow::anyhow!("Unexpected SMTP response: {}", trimmed));
        }
    }
    
    Ok(responses)
}

async fn send_smtp_mail(mut stream: TcpStream, email: &Email) -> anyhow::Result<()> {
    let (read_half, write_half) = stream.split();
    let mut writer = BufWriter::new(write_half);
    let mut reader = BufReader::new(read_half);
    let mut response = String::new();

    // Lire le message de bienvenue
    reader.read_line(&mut response).await?;
    tracing::debug!("Server greeting: {}", response.trim());
    
    // EHLO
    writer.write_all(b"EHLO localhost\r\n").await?;
    writer.flush().await?;
    response.clear();
    reader.read_line(&mut response).await?;
    tracing::debug!("EHLO response: {}", response.trim());
    
    // MAIL FROM
    let mail_from = format!("MAIL FROM:<{}>\r\n", email.sender);
    writer.write_all(mail_from.as_bytes()).await?;
    writer.flush().await?;
    response.clear();
    reader.read_line(&mut response).await?;
    tracing::debug!("MAIL FROM response: {}", response.trim());
    
    // RCPT TO
    let rcpt_to = format!("RCPT TO:<{}>\r\n", email.receiver);
    writer.write_all(rcpt_to.as_bytes()).await?;
    writer.flush().await?;
    response.clear();
    reader.read_line(&mut response).await?;
    tracing::debug!("RCPT TO response: {}", response.trim());
    
    // DATA
    writer.write_all(b"DATA\r\n").await?;
    writer.flush().await?;
    response.clear();
    reader.read_line(&mut response).await?;
    tracing::debug!("DATA response: {}", response.trim());
    
    // Contenu du mail
    tracing::debug!("Sending email content (length: {} bytes)", email.data.len());
    writer.write_all(format!("From: <{}>\r\n", email.sender).as_bytes()).await?;
    writer.write_all(format!("To: <{}>\r\n", email.receiver).as_bytes()).await?;
    writer.write_all(format!("Subject: {}\r\n\r\n", email.subject).as_bytes()).await?;
    writer.write_all(email.data.as_bytes()).await?;
    writer.write_all(b"\r\n.\r\n").await?;
    writer.flush().await?;
    response.clear();
    reader.read_line(&mut response).await?;
    tracing::debug!("End of data response: {}", response.trim());
    
    // QUIT
    writer.write_all(b"QUIT\r\n").await?;
    writer.flush().await?;
    response.clear();
    reader.read_line(&mut response).await?;
    tracing::debug!("QUIT response: {}", response.trim());

    Ok(())
}

async fn send_smtp_mail_tls(mut stream: TcpStream, email: &Email) -> anyhow::Result<()> {
    let (read_half, write_half) = stream.split();
    let mut writer = BufWriter::new(write_half);
    let mut reader = BufReader::new(read_half);
    
    // Lire le message de bienvenue
    let mut greeting = String::new();
    reader.read_line(&mut greeting).await?;
    tracing::debug!("Server greeting: {}", greeting.trim());
    
    // EHLO
    writer.write_all(b"EHLO localhost\r\n").await?;
    writer.flush().await?;
    
    // Lire toutes les réponses EHLO
    let responses = read_smtp_response(&mut reader).await?;
    
    // Vérifier si STARTTLS est supporté
    if !responses.iter().any(|r| r.contains("STARTTLS")) {
        return Err(anyhow::anyhow!("STARTTLS not supported by server"));
    }
    
    // STARTTLS
    writer.write_all(b"STARTTLS\r\n").await?;
    writer.flush().await?;
    
    let mut response = String::new();
    reader.read_line(&mut response).await?;
    if !response.starts_with("220") {
        return Err(anyhow::anyhow!("STARTTLS failed: {}", response));
    }
    
    // Établir la connexion TLS
    let tls_connector = native_tls::TlsConnector::builder()
        .min_protocol_version(Some(native_tls::Protocol::Tlsv12))
        .build()?;
    let tls_connector = tokio_native_tls::TlsConnector::from(tls_connector);
    let tls_stream = tls_connector.connect("smtp.gmail.com", stream).await?;
    
    let (read_half, write_half) = tokio::io::split(tls_stream);
    let mut writer = BufWriter::new(write_half);
    let mut reader = BufReader::new(read_half);
    
    // EHLO après TLS
    writer.write_all(b"EHLO localhost\r\n").await?;
    writer.flush().await?;
    response.clear();
    reader.read_line(&mut response).await?;
    
    // Continuer avec le reste du protocole SMTP...
    // MAIL FROM, RCPT TO, DATA, etc.
    let mail_from = format!("MAIL FROM:<{}>\r\n", email.sender);
    writer.write_all(mail_from.as_bytes()).await?;
    writer.flush().await?;
    response.clear();
    reader.read_line(&mut response).await?;
    
    let rcpt_to = format!("RCPT TO:<{}>\r\n", email.receiver);
    writer.write_all(rcpt_to.as_bytes()).await?;
    writer.flush().await?;
    response.clear();
    reader.read_line(&mut response).await?;
    
    // ... reste du code pour l'envoi du mail ...
    
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    listen().await
}

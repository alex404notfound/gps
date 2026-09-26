// Jackson Coxson
//! Manual TLS 1.2 PSK-AES128-CBC-SHA implementation.
//!
//! This implements just enough of TLS 1.2 to negotiate
//! `TLS_PSK_WITH_AES_128_CBC_SHA` (0x008C) with no certificates or DH.
//! The result is an encrypted stream suitable for CDTunnel.
//! We did this ourselves because rustls won't :(

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::Sha256;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tracing::debug;

use crate::IdeviceError;

// TLS 1.2 constants
const TLS_12: [u8; 2] = [0x03, 0x03];
const CT_HANDSHAKE: u8 = 0x16;
const CT_CHANGE_CIPHER_SPEC: u8 = 0x14;
const CT_APPLICATION_DATA: u8 = 0x17;
/// Maximum plaintext bytes per TLS record (RFC 5246 §6.2.1)
const TLS_MAX_PLAINTEXT: usize = 16384;
const HS_CLIENT_HELLO: u8 = 0x01;
const HS_SERVER_HELLO: u8 = 0x02;
const HS_SERVER_HELLO_DONE: u8 = 0x0E;
const HS_CLIENT_KEY_EXCHANGE: u8 = 0x10;
const HS_FINISHED: u8 = 0x14;
// Offer both; device typically picks AES256-CBC-SHA384
const PSK_CIPHER_SUITES: &[[u8; 2]] = &[
    [0x00, 0xAF], // TLS_PSK_WITH_AES_256_CBC_SHA384 (preferred by iOS)
    [0x00, 0x8C], // TLS_PSK_WITH_AES_128_CBC_SHA (fallback)
];

type HmacSha256 = Hmac<Sha256>;
type HmacSha1 = Hmac<Sha1>;
type HmacSha384 = Hmac<sha2::Sha384>;
type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// Selected cipher suite parameters
#[derive(Clone, Copy, Debug)]
enum CipherSuite {
    Aes128CbcSha,    // 0x008C: 16-byte key, 20-byte MAC (SHA1), PRF=SHA256
    Aes256CbcSha384, // 0x00AF: 32-byte key, 48-byte MAC (SHA384), PRF=SHA384
}

impl CipherSuite {
    fn from_bytes(b: [u8; 2]) -> Option<Self> {
        match b {
            [0x00, 0x8C] => Some(Self::Aes128CbcSha),
            [0x00, 0xAF] => Some(Self::Aes256CbcSha384),
            _ => None,
        }
    }
    fn enc_key_len(self) -> usize {
        match self {
            Self::Aes128CbcSha => 16,
            Self::Aes256CbcSha384 => 32,
        }
    }
    fn mac_key_len(self) -> usize {
        match self {
            Self::Aes128CbcSha => 20,
            Self::Aes256CbcSha384 => 48,
        }
    }
}

struct KeyBlock {
    client_mac_key: Vec<u8>,
    server_mac_key: Vec<u8>,
    client_write_key: Vec<u8>,
    server_write_key: Vec<u8>,
    suite: CipherSuite,
}

fn hmac_compute(key: &[u8], data: &[u8], suite: CipherSuite) -> Vec<u8> {
    match suite {
        CipherSuite::Aes128CbcSha => {
            // PRF uses SHA256 for P_hash, but record MAC uses SHA1
            let mut mac = HmacSha256::new_from_slice(key).unwrap();
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        CipherSuite::Aes256CbcSha384 => {
            let mut mac = HmacSha384::new_from_slice(key).unwrap();
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

/// TLS 1.2 PRF: P_hash with the suite's PRF hash
fn prf(secret: &[u8], label: &[u8], seed: &[u8], len: usize, suite: CipherSuite) -> Vec<u8> {
    let mut label_seed = label.to_vec();
    label_seed.extend_from_slice(seed);

    let mut a = hmac_compute(secret, &label_seed, suite);
    let mut out = Vec::with_capacity(len);

    while out.len() < len {
        let mut input = a.clone();
        input.extend_from_slice(&label_seed);
        out.extend_from_slice(&hmac_compute(secret, &input, suite));
        a = hmac_compute(secret, &a, suite);
    }
    out.truncate(len);
    out
}

/// PSK premaster secret (RFC 4279 §2)
fn psk_premaster(psk: &[u8]) -> Vec<u8> {
    let psk_len = psk.len() as u16;
    let mut pm = Vec::with_capacity(4 + psk.len() * 2);
    pm.extend_from_slice(&psk_len.to_be_bytes());
    pm.extend(std::iter::repeat_n(0u8, psk.len()));
    pm.extend_from_slice(&psk_len.to_be_bytes());
    pm.extend_from_slice(psk);
    pm
}

fn derive_master_secret(
    psk: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    suite: CipherSuite,
) -> Vec<u8> {
    let premaster = psk_premaster(psk);
    let mut seed = client_random.to_vec();
    seed.extend_from_slice(server_random);
    prf(&premaster, b"master secret", &seed, 48, suite)
}

fn derive_key_block(
    master: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    suite: CipherSuite,
) -> KeyBlock {
    let mut seed = server_random.to_vec();
    seed.extend_from_slice(client_random);
    let mac_len = suite.mac_key_len();
    let key_len = suite.enc_key_len();
    let total = mac_len * 2 + key_len * 2;
    let kb = prf(master, b"key expansion", &seed, total, suite);
    let mut pos = 0;
    let client_mac_key = kb[pos..pos + mac_len].to_vec();
    pos += mac_len;
    let server_mac_key = kb[pos..pos + mac_len].to_vec();
    pos += mac_len;
    let client_write_key = kb[pos..pos + key_len].to_vec();
    pos += key_len;
    let server_write_key = kb[pos..pos + key_len].to_vec();
    KeyBlock {
        client_mac_key,
        server_mac_key,
        client_write_key,
        server_write_key,
        suite,
    }
}

fn compute_mac(mac_key: &[u8], seq: u64, ct: u8, data: &[u8], suite: CipherSuite) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.extend_from_slice(&[ct, 0x03, 0x03]);
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);

    match suite {
        CipherSuite::Aes128CbcSha => {
            let mut mac = HmacSha1::new_from_slice(mac_key).unwrap();
            mac.update(&buf);
            mac.finalize().into_bytes().to_vec()
        }
        CipherSuite::Aes256CbcSha384 => {
            let mut mac = HmacSha384::new_from_slice(mac_key).unwrap();
            mac.update(&buf);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

fn encrypt_record(keys: &KeyBlock, seq: u64, ct: u8, plaintext: &[u8]) -> Vec<u8> {
    let mac = compute_mac(&keys.client_mac_key, seq, ct, plaintext, keys.suite);

    let mut payload = plaintext.to_vec();
    payload.extend_from_slice(&mac);

    // PKCS#7 padding (block size = 16 for both AES-128 and AES-256)
    let pad_len = 16 - (payload.len() % 16);
    payload.extend(std::iter::repeat_n(pad_len as u8 - 1, pad_len));

    let mut iv = [0u8; 16];
    rand::fill(&mut iv);

    let ciphertext = match keys.suite {
        CipherSuite::Aes128CbcSha => {
            let enc = Aes128CbcEnc::new(keys.client_write_key[..16].into(), &iv.into());
            enc.encrypt_padded_vec_mut::<aes::cipher::block_padding::NoPadding>(&payload)
        }
        CipherSuite::Aes256CbcSha384 => {
            let enc = Aes256CbcEnc::new(keys.client_write_key[..32].into(), &iv.into());
            enc.encrypt_padded_vec_mut::<aes::cipher::block_padding::NoPadding>(&payload)
        }
    };

    let mut result = iv.to_vec();
    result.extend_from_slice(&ciphertext);
    result
}

fn decrypt_record(
    keys: &KeyBlock,
    is_server: bool,
    seq: u64,
    ct: u8,
    encrypted: &[u8],
) -> Result<Vec<u8>, IdeviceError> {
    if encrypted.len() < 16 {
        return Err(IdeviceError::InternalError("TLS record too short".into()));
    }

    let iv = &encrypted[..16];
    let ciphertext = &encrypted[16..];
    let read_key = if is_server {
        &keys.server_write_key
    } else {
        &keys.client_write_key
    };
    let mac_key = if is_server {
        &keys.server_mac_key
    } else {
        &keys.client_mac_key
    };

    let decrypted = match keys.suite {
        CipherSuite::Aes128CbcSha => {
            let dec = Aes128CbcDec::new(read_key[..16].into(), iv.into());
            dec.decrypt_padded_vec_mut::<aes::cipher::block_padding::NoPadding>(ciphertext)
                .map_err(|e| IdeviceError::InternalError(format!("CBC decrypt: {e}")))?
        }
        CipherSuite::Aes256CbcSha384 => {
            let dec = Aes256CbcDec::new(read_key[..32].into(), iv.into());
            dec.decrypt_padded_vec_mut::<aes::cipher::block_padding::NoPadding>(ciphertext)
                .map_err(|e| IdeviceError::InternalError(format!("CBC decrypt: {e}")))?
        }
    };

    let content_len = tls_padding_content_len(&decrypted)?;
    let mac_len = keys.suite.mac_key_len();
    if content_len < mac_len {
        return Err(IdeviceError::InternalError(
            "Decrypted content too short for MAC".into(),
        ));
    }

    let plaintext = &decrypted[..content_len - mac_len];
    let received_mac = &decrypted[content_len - mac_len..content_len];

    let expected_mac = compute_mac(mac_key, seq, ct, plaintext, keys.suite);
    if received_mac != expected_mac.as_slice() {
        return Err(IdeviceError::InternalError(
            "TLS MAC verification failed".into(),
        ));
    }

    Ok(plaintext.to_vec())
}

fn tls_padding_content_len(decrypted: &[u8]) -> Result<usize, IdeviceError> {
    let Some(&pad_value) = decrypted.last() else {
        return Err(IdeviceError::InternalError("Empty decrypted data".into()));
    };
    let padding_len = usize::from(pad_value) + 1;
    if padding_len > decrypted.len()
        || decrypted[decrypted.len() - padding_len..]
            .iter()
            .any(|byte| *byte != pad_value)
    {
        return Err(IdeviceError::InternalError("Invalid TLS CBC padding".into()));
    }
    Ok(decrypted.len() - padding_len)
}

fn finished_verify_data(
    master: &[u8],
    label: &[u8],
    transcript: &[u8],
    suite: CipherSuite,
) -> [u8; 12] {
    use sha2::Digest;
    let hash: Vec<u8> = match suite {
        CipherSuite::Aes128CbcSha => sha2::Sha256::digest(transcript).to_vec(),
        CipherSuite::Aes256CbcSha384 => sha2::Sha384::digest(transcript).to_vec(),
    };
    prf(master, label, &hash, 12, suite).try_into().unwrap()
}

fn verify_server_finished(
    plaintext: &[u8],
    master: &[u8],
    transcript: &[u8],
    suite: CipherSuite,
) -> Result<(), IdeviceError> {
    if plaintext.len() != 16
        || plaintext[0] != HS_FINISHED
        || plaintext[1..4] != [0, 0, 12]
    {
        return Err(IdeviceError::InternalError(
            "TLS server Finished is missing or malformed".into(),
        ));
    }
    let expected = finished_verify_data(master, b"server finished", transcript, suite);
    let mismatch = plaintext[4..]
        .iter()
        .zip(expected.iter())
        .fold(0_u8, |acc, (received, expected)| acc | (received ^ expected));
    if mismatch != 0 {
        return Err(IdeviceError::InternalError(
            "TLS server Finished verify_data mismatch".into(),
        ));
    }
    Ok(())
}

fn make_record(ct: u8, payload: &[u8]) -> Vec<u8> {
    let mut rec = vec![ct, 0x03, 0x03];
    rec.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    rec.extend_from_slice(payload);
    rec
}

fn make_handshake(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut msg = vec![msg_type];
    let len = body.len() as u32;
    msg.extend_from_slice(&len.to_be_bytes()[1..]); // 3-byte length
    msg.extend_from_slice(body);
    msg
}

async fn read_record<S: AsyncRead + Unpin>(stream: &mut S) -> Result<(u8, Vec<u8>), IdeviceError> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;
    let ct = header[0];
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await?;
    Ok((ct, payload))
}

/// Extract handshake messages from a record payload.
/// A single record can contain multiple handshake messages.
fn parse_handshake_messages(data: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut msgs = Vec::new();
    let mut pos = 0;
    while pos + 4 <= data.len() {
        let msg_type = data[pos];
        let msg_len = u32::from_be_bytes([0, data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        if pos + 4 + msg_len > data.len() {
            break;
        }
        msgs.push((msg_type, data[pos..pos + 4 + msg_len].to_vec()));
        pos += 4 + msg_len;
    }
    msgs
}

/// Perform TLS 1.2 PSK handshake and return an encrypted stream.
pub async fn tls_psk_handshake<S: AsyncRead + AsyncWrite + Unpin + Send>(
    mut stream: S,
    psk: &[u8],
) -> Result<TlsPskStream<S>, IdeviceError> {
    let mut client_random = [0u8; 32];
    rand::fill(&mut client_random);
    let mut server_random = [0u8; 32];
    let mut selected_cipher = [0u8; 2];
    let mut transcript = Vec::new();

    // 1. ClientHello
    let mut ch_body = Vec::new();
    ch_body.extend_from_slice(&TLS_12);
    ch_body.extend_from_slice(&client_random);
    ch_body.push(0x00); // session_id len = 0
    let suites_len = (PSK_CIPHER_SUITES.len() * 2) as u16;
    ch_body.extend_from_slice(&suites_len.to_be_bytes());
    for suite in PSK_CIPHER_SUITES {
        ch_body.extend_from_slice(suite);
    }
    ch_body.extend_from_slice(&[0x01, 0x00]); // compression: null
    let ch = make_handshake(HS_CLIENT_HELLO, &ch_body);
    transcript.extend_from_slice(&ch);
    stream.write_all(&make_record(CT_HANDSHAKE, &ch)).await?;
    debug!("Sent ClientHello");

    // 2. Read ServerHello, optional ServerKeyExchange (PSK hint), ServerHelloDone
    loop {
        let (ct, payload) = read_record(&mut stream).await?;
        if ct == 21 {
            // TLS Alert
            let level = payload.first().copied().unwrap_or(0);
            let desc = payload.get(1).copied().unwrap_or(0);
            return Err(IdeviceError::InternalError(format!(
                "TLS Alert: level={level} desc={desc} ({})",
                match desc {
                    0 => "close_notify",
                    10 => "unexpected_message",
                    20 => "bad_record_mac",
                    40 => "handshake_failure",
                    47 => "illegal_parameter",
                    70 => "protocol_version",
                    71 => "insufficient_security",
                    80 => "internal_error",
                    _ => "unknown",
                }
            )));
        }
        if ct != CT_HANDSHAKE {
            return Err(IdeviceError::InternalError(format!(
                "Expected handshake, got ct={ct}"
            )));
        }
        transcript.extend_from_slice(&payload);

        for (msg_type, _msg_bytes) in parse_handshake_messages(&payload) {
            match msg_type {
                HS_SERVER_HELLO => {
                    // ServerHello layout (after 4-byte handshake header):
                    // 2 bytes version, 32 bytes random, 1 byte session_id_len,
                    // session_id, 2 bytes cipher_suite
                    if payload.len() >= 4 + 2 + 32 {
                        server_random.copy_from_slice(&payload[6..38]);
                        let sid_len = payload[38] as usize;
                        if payload.len() >= 39 + sid_len + 2 {
                            selected_cipher
                                .copy_from_slice(&payload[39 + sid_len..39 + sid_len + 2]);
                        }
                    }
                    debug!("Got ServerHello, cipher={selected_cipher:02x?}");
                }
                HS_SERVER_HELLO_DONE => {
                    debug!("Got ServerHelloDone");
                }
                _ => {
                    debug!("Got handshake msg type {msg_type}");
                }
            }
        }

        // Check if we've seen ServerHelloDone
        if payload.contains(&HS_SERVER_HELLO_DONE) && payload.len() >= 4 {
            // Simple check: if ServerHelloDone is in the payload, we're done
            // ServerHelloDone is a 0-length message: [0x0E, 0x00, 0x00, 0x00]
            if payload
                .windows(4)
                .any(|w| w == [HS_SERVER_HELLO_DONE, 0x00, 0x00, 0x00])
            {
                break;
            }
        }
    }

    // 3. Determine cipher suite and derive keys
    let suite = CipherSuite::from_bytes(selected_cipher).ok_or_else(|| {
        IdeviceError::InternalError(format!(
            "Server selected unsupported cipher: {selected_cipher:02x?}"
        ))
    })?;
    debug!("Using cipher suite: {suite:?}");

    let master = derive_master_secret(psk, &client_random, &server_random, suite);
    let keys = derive_key_block(&master, &client_random, &server_random, suite);

    // 4. ClientKeyExchange (empty PSK identity)
    let cke = make_handshake(HS_CLIENT_KEY_EXCHANGE, &[0x00, 0x00]);
    transcript.extend_from_slice(&cke);
    stream.write_all(&make_record(CT_HANDSHAKE, &cke)).await?;
    debug!("Sent ClientKeyExchange");

    // 5. ChangeCipherSpec
    stream
        .write_all(&make_record(CT_CHANGE_CIPHER_SPEC, &[0x01]))
        .await?;
    debug!("Sent ChangeCipherSpec");

    // 6. Client Finished (encrypted)
    let vd = finished_verify_data(&master, b"client finished", &transcript, suite);
    let fin = make_handshake(HS_FINISHED, &vd);
    transcript.extend_from_slice(&fin);
    let enc_fin = encrypt_record(&keys, 0, CT_HANDSHAKE, &fin);
    stream
        .write_all(&make_record(CT_HANDSHAKE, &enc_fin))
        .await?;
    stream.flush().await?;
    debug!("Sent encrypted Finished");

    // 7. Read server ChangeCipherSpec + Finished
    let mut server_seq: u64 = 0;
    let mut received_ccs = false;
    loop {
        let (ct, payload) = read_record(&mut stream).await?;
        if ct == 21 {
            let level = payload.first().copied().unwrap_or(0);
            let desc = payload.get(1).copied().unwrap_or(0);
            return Err(IdeviceError::InternalError(format!(
                "TLS Alert after Finished: level={level} desc={desc}"
            )));
        }
        match ct {
            CT_CHANGE_CIPHER_SPEC => {
                if received_ccs || payload != [0x01] {
                    return Err(IdeviceError::InternalError(
                        "TLS server ChangeCipherSpec is malformed or duplicated".into(),
                    ));
                }
                received_ccs = true;
                debug!("Got server ChangeCipherSpec");
            }
            CT_HANDSHAKE if received_ccs => {
                let plaintext = decrypt_record(&keys, true, server_seq, CT_HANDSHAKE, &payload)?;
                server_seq += 1;
                verify_server_finished(&plaintext, &master, &transcript, suite)?;
                debug!("Server Finished verified");
                break;
            }
            _ => {
                return Err(IdeviceError::InternalError(format!(
                    "Unexpected TLS record type {ct} before server Finished"
                )));
            }
        }
    }

    debug!("TLS-PSK handshake complete");

    Ok(TlsPskStream {
        inner: stream,
        keys,
        write_seq: 1, // seq 0 was used for client Finished
        read_seq: server_seq,
        read_buf: Vec::new(),
        pending_record: Vec::new(),
        pending_record_total: 0,
        write_buf: Vec::new(),
    })
}

/// An encrypted TLS-PSK stream implementing AsyncRead + AsyncWrite.
pub struct TlsPskStream<S> {
    inner: S,
    keys: KeyBlock,
    write_seq: u64,
    read_seq: u64,
    /// Decrypted plaintext buffered for reads
    read_buf: Vec<u8>,
    /// Partial inbound TLS record being assembled
    pending_record: Vec<u8>,
    /// Expected total bytes for the current inbound record (5 + body_len), 0 if unknown
    pending_record_total: usize,
    /// Partial outbound TLS record waiting to be flushed
    write_buf: Vec<u8>,
}

impl<S> std::fmt::Debug for TlsPskStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsPskStream")
            .field("write_seq", &self.write_seq)
            .field("read_seq", &self.read_seq)
            .finish()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> TlsPskStream<S> {
    /// Encrypt and send application data, splitting into multiple TLS records if needed.
    pub async fn write_app_data(&mut self, data: &[u8]) -> Result<(), IdeviceError> {
        for chunk in data.chunks(TLS_MAX_PLAINTEXT) {
            let encrypted = encrypt_record(&self.keys, self.write_seq, CT_APPLICATION_DATA, chunk);
            self.write_seq += 1;
            self.inner
                .write_all(&make_record(CT_APPLICATION_DATA, &encrypted))
                .await?;
        }
        self.inner.flush().await?;
        Ok(())
    }

    /// Read and decrypt application data.
    pub async fn read_app_data(&mut self) -> Result<Vec<u8>, IdeviceError> {
        let (ct, payload) = read_record(&mut self.inner).await?;
        if ct != CT_APPLICATION_DATA {
            return Err(IdeviceError::InternalError(format!(
                "Expected application data, got ct={ct}"
            )));
        }
        let plaintext = decrypt_record(
            &self.keys,
            true,
            self.read_seq,
            CT_APPLICATION_DATA,
            &payload,
        )?;
        self.read_seq += 1;
        Ok(plaintext)
    }
}

// AsyncRead: assemble complete TLS records across multiple poll_read calls
impl<S: AsyncRead + AsyncWrite + Unpin + Send + Sync> AsyncRead for TlsPskStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // 1. Serve from decrypted buffer first
        if !this.read_buf.is_empty() {
            let n = buf.remaining().min(this.read_buf.len());
            buf.put_slice(&this.read_buf[..n]);
            this.read_buf.drain(..n);
            return Poll::Ready(Ok(()));
        }

        // 2. Continue assembling a TLS record
        loop {
            // If we have the header (5 bytes), compute total needed
            if this.pending_record.len() >= 5 && this.pending_record_total == 0 {
                let body_len =
                    u16::from_be_bytes([this.pending_record[3], this.pending_record[4]]) as usize;
                this.pending_record_total = 5 + body_len;
            }

            // If we have a complete record, decrypt it
            if this.pending_record_total > 0
                && this.pending_record.len() >= this.pending_record_total
            {
                let ct = this.pending_record[0];
                let body = this.pending_record[5..this.pending_record_total].to_vec();
                this.pending_record.drain(..this.pending_record_total);
                this.pending_record_total = 0;

                match decrypt_record(&this.keys, true, this.read_seq, ct, &body) {
                    Ok(plaintext) => {
                        this.read_seq += 1;
                        let n = buf.remaining().min(plaintext.len());
                        buf.put_slice(&plaintext[..n]);
                        if n < plaintext.len() {
                            this.read_buf.extend_from_slice(&plaintext[n..]);
                        }
                        return Poll::Ready(Ok(()));
                    }
                    Err(e) => {
                        tracing::warn!(
                            "TLS decrypt failed (ct={ct}, seq={}, body_len={}): {e}",
                            this.read_seq,
                            body.len()
                        );
                        return Poll::Ready(Err(std::io::Error::other(format!(
                            "TLS decrypt: {e}"
                        ))));
                    }
                }
            }

            // Need more data from the underlying stream
            let mut tmp = [0u8; 16384];
            let mut tmp_buf = ReadBuf::new(&mut tmp);
            match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let n = tmp_buf.filled().len();
                    if n == 0 {
                        return Poll::Ready(Ok(())); // EOF
                    }
                    this.pending_record.extend_from_slice(&tmp[..n]);
                    // Loop back to check if we now have a complete record
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + Sync> AsyncWrite for TlsPskStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        // An empty write must not consume a TLS sequence number or emit a
        // record. As with a buffered writer, callers use flush to drain an
        // earlier accepted write.
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Flush any pending partial write first
        while !this.write_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(n)) => { this.write_buf.drain(..n); }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // Clamp to TLS max record size to avoid oversized records
        let chunk = &data[..data.len().min(TLS_MAX_PLAINTEXT)];

        // Encrypt the new data into a TLS record
        let encrypted = encrypt_record(&this.keys, this.write_seq, CT_APPLICATION_DATA, chunk);
        let record = make_record(CT_APPLICATION_DATA, &encrypted);
        this.write_seq += 1;

        match Pin::new(&mut this.inner).poll_write(cx, &record) {
            Poll::Ready(Ok(0)) => {
                this.write_seq -= 1;
                Poll::Ready(Err(io::ErrorKind::WriteZero.into()))
            }
            Poll::Ready(Ok(written)) => {
                if written < record.len() {
                    // Buffer the unsent remainder
                    this.write_buf.extend_from_slice(&record[written..]);
                }
                Poll::Ready(Ok(chunk.len()))
            }
            Poll::Ready(Err(e)) => {
                this.write_seq -= 1;
                Poll::Ready(Err(e))
            }
            Poll::Pending => {
                // We now own this plaintext in an encrypted record. Report it
                // as consumed exactly once; returning Pending here would make
                // AsyncWrite callers retry and duplicate the application data.
                this.write_buf = record;
                Poll::Ready(Ok(chunk.len()))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // Flush buffered write data first
        while !this.write_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(n)) => { this.write_buf.drain(..n); }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut this = self;
        match this.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.get_mut().inner).poll_shutdown(cx),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod gps_tls_strict_tests {
    use super::*;

    #[test]
    fn server_finished_requires_complete_matching_verify_data() {
        let master = [0x42; 48];
        let transcript = b"test TLS handshake transcript";
        let suite = CipherSuite::Aes128CbcSha;
        let expected = finished_verify_data(&master, b"server finished", transcript, suite);
        let valid = make_handshake(HS_FINISHED, &expected);
        assert!(verify_server_finished(&valid, &master, transcript, suite).is_ok());

        let mut mismatched = valid.clone();
        mismatched[4] ^= 1;
        assert!(verify_server_finished(&mismatched, &master, transcript, suite).is_err());
        assert!(verify_server_finished(&[], &master, transcript, suite).is_err());
        assert!(verify_server_finished(&valid[..15], &master, transcript, suite).is_err());
        let mut malformed = valid.clone();
        malformed[3] = 11;
        assert!(verify_server_finished(&malformed, &master, transcript, suite).is_err());
    }

    #[test]
    fn malformed_tls_padding_is_rejected_without_panicking() {
        assert!(tls_padding_content_len(&[]).is_err());
        assert!(tls_padding_content_len(&[0xff]).is_err());
        assert!(tls_padding_content_len(&[1, 2, 2]).is_err());
        assert_eq!(tls_padding_content_len(&[0x42, 1, 1]).unwrap(), 1);
    }

    #[tokio::test]
    async fn missing_server_finished_does_not_complete_handshake() {
        let (client, mut server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let mut hello_body = Vec::new();
            hello_body.extend_from_slice(&TLS_12);
            hello_body.extend_from_slice(&[0x33; 32]);
            hello_body.push(0); // no session ID
            hello_body.extend_from_slice(&[0x00, 0x8c]);
            hello_body.push(0); // null compression
            let mut hello = make_handshake(HS_SERVER_HELLO, &hello_body);
            hello.extend_from_slice(&make_handshake(HS_SERVER_HELLO_DONE, &[]));
            server.write_all(&make_record(CT_HANDSHAKE, &hello)).await.unwrap();
            server.write_all(&make_record(CT_CHANGE_CIPHER_SPEC, &[1])).await.unwrap();
            for _ in 0..4 {
                let _ = read_record(&mut server).await.unwrap();
            }
            // Closing without an encrypted Finished must fail the client handshake.
        });
        let error = tls_psk_handshake(client, &[0x55; 32]).await.err().unwrap();
        assert!(matches!(
            error,
            IdeviceError::Socket(ref io_error)
                if io_error.kind() == std::io::ErrorKind::UnexpectedEof
        ), "expected EOF while waiting for server Finished, got {error:?}");
        server_task.await.unwrap();
    }
}

#[cfg(test)]
mod gps_tls_write_tests {
    use super::*;
    use std::collections::VecDeque;
    use std::task::Waker;

    enum WriteStep {
        Pending,
        Accept(usize),
        Zero,
        Error(io::ErrorKind),
    }

    struct ScriptedIo {
        steps: VecDeque<WriteStep>,
        sent: Vec<u8>,
        flushes: usize,
        shutdowns: usize,
    }

    impl AsyncRead for ScriptedIo {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ScriptedIo {
        fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
            match self.steps.pop_front().unwrap_or(WriteStep::Accept(usize::MAX)) {
                WriteStep::Pending => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                WriteStep::Accept(max) => {
                    let n = max.min(data.len());
                    self.sent.extend_from_slice(&data[..n]);
                    Poll::Ready(Ok(n))
                }
                WriteStep::Zero => Poll::Ready(Ok(0)),
                WriteStep::Error(kind) => Poll::Ready(Err(kind.into())),
            }
        }

        fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.flushes += 1;
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.shutdowns += 1;
            Poll::Ready(Ok(()))
        }
    }

    fn scripted_stream(steps: Vec<WriteStep>) -> TlsPskStream<ScriptedIo> {
        TlsPskStream {
            inner: ScriptedIo {
                steps: steps.into(),
                sent: Vec::new(),
                flushes: 0,
                shutdowns: 0,
            },
            // Identical client/server keys let the test decrypt outbound
            // records with the existing server-record decoder.
            keys: KeyBlock {
                client_mac_key: vec![0x11; 20],
                server_mac_key: vec![0x11; 20],
                client_write_key: vec![0x22; 16],
                server_write_key: vec![0x22; 16],
                suite: CipherSuite::Aes128CbcSha,
            },
            write_seq: 0,
            read_seq: 0,
            read_buf: Vec::new(),
            pending_record: Vec::new(),
            pending_record_total: 0,
            write_buf: Vec::new(),
        }
    }

    fn write_once(stream: &mut TlsPskStream<ScriptedIo>, data: &[u8]) -> Poll<io::Result<usize>> {
        let mut cx = Context::from_waker(Waker::noop());
        Pin::new(stream).poll_write(&mut cx, data)
    }

    fn flush_once(stream: &mut TlsPskStream<ScriptedIo>) -> Poll<io::Result<()>> {
        let mut cx = Context::from_waker(Waker::noop());
        Pin::new(stream).poll_flush(&mut cx)
    }

    fn shutdown_once(stream: &mut TlsPskStream<ScriptedIo>) -> Poll<io::Result<()>> {
        let mut cx = Context::from_waker(Waker::noop());
        Pin::new(stream).poll_shutdown(&mut cx)
    }

    fn outbound_plaintexts(stream: &TlsPskStream<ScriptedIo>) -> Vec<Vec<u8>> {
        let mut records = Vec::new();
        let mut remaining = stream.inner.sent.as_slice();
        while !remaining.is_empty() {
            assert!(remaining.len() >= 5);
            assert_eq!(remaining[0], CT_APPLICATION_DATA);
            let body_len = u16::from_be_bytes([remaining[3], remaining[4]]) as usize;
            assert!(remaining.len() >= 5 + body_len);
            let body = &remaining[5..5 + body_len];
            records.push(decrypt_record(&stream.keys, true, records.len() as u64, CT_APPLICATION_DATA, body).unwrap());
            remaining = &remaining[5 + body_len..];
        }
        records
    }

    #[test]
    fn pending_and_partial_writes_accept_each_plaintext_once() {
        let mut stream = scripted_stream(vec![
            WriteStep::Pending,
            WriteStep::Accept(7),
            WriteStep::Pending,
            WriteStep::Accept(usize::MAX),
            WriteStep::Accept(usize::MAX),
        ]);
        assert!(matches!(write_once(&mut stream, b"first"), Poll::Ready(Ok(5))));
        assert_eq!(stream.write_seq, 1);
        assert!(!stream.write_buf.is_empty());
        assert!(write_once(&mut stream, b"second").is_pending());
        assert_eq!(stream.write_seq, 1);
        assert!(matches!(write_once(&mut stream, b"second"), Poll::Ready(Ok(6))));
        assert!(matches!(flush_once(&mut stream), Poll::Ready(Ok(()))));
        assert_eq!(stream.write_seq, 2);
        assert_eq!(outbound_plaintexts(&stream), vec![b"first".to_vec(), b"second".to_vec()]);
    }

    #[test]
    fn partial_record_drains_on_flush() {
        let mut stream = scripted_stream(vec![WriteStep::Accept(3), WriteStep::Accept(usize::MAX)]);
        assert!(matches!(write_once(&mut stream, b"partial"), Poll::Ready(Ok(7))));
        assert!(!stream.write_buf.is_empty());
        assert!(matches!(flush_once(&mut stream), Poll::Ready(Ok(()))));
        assert!(stream.write_buf.is_empty());
        assert_eq!(stream.inner.flushes, 1);
        assert_eq!(outbound_plaintexts(&stream), vec![b"partial".to_vec()]);
    }

    #[test]
    fn zero_and_error_do_not_spin_or_acknowledge_new_plaintext() {
        let mut zero = scripted_stream(vec![WriteStep::Zero]);
        assert!(matches!(write_once(&mut zero, b"x"), Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::WriteZero));
        assert_eq!(zero.write_seq, 0);
        assert!(zero.write_buf.is_empty());

        let mut error = scripted_stream(vec![WriteStep::Error(io::ErrorKind::BrokenPipe)]);
        assert!(matches!(write_once(&mut error, b"x"), Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::BrokenPipe));
        assert_eq!(error.write_seq, 0);

        let mut flush_zero = scripted_stream(vec![WriteStep::Pending, WriteStep::Zero]);
        assert!(matches!(write_once(&mut flush_zero, b"x"), Poll::Ready(Ok(1))));
        assert!(matches!(flush_once(&mut flush_zero), Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::WriteZero));
        assert!(!flush_zero.write_buf.is_empty());
    }

    #[test]
    fn shutdown_drains_pending_record_and_empty_write_makes_no_record() {
        let mut stream = scripted_stream(vec![WriteStep::Pending, WriteStep::Pending, WriteStep::Accept(usize::MAX)]);
        assert!(matches!(write_once(&mut stream, b""), Poll::Ready(Ok(0))));
        assert_eq!(stream.write_seq, 0);
        assert!(matches!(write_once(&mut stream, b"last"), Poll::Ready(Ok(4))));
        assert!(shutdown_once(&mut stream).is_pending());
        assert_eq!(stream.inner.shutdowns, 0);
        assert!(matches!(shutdown_once(&mut stream), Poll::Ready(Ok(()))));
        assert_eq!(stream.inner.flushes, 1);
        assert_eq!(stream.inner.shutdowns, 1);
        assert_eq!(outbound_plaintexts(&stream), vec![b"last".to_vec()]);
    }
}

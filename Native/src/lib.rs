//! Authenticated on-device developer location transport.
//!
//! The C ABI is synchronous so Swift must invoke it on a background executor.
//! A dedicated Tokio worker owns the tunnel and DVT channel for the entire
//! session: dropping the channel after `set` can end location simulation.

use std::ffi::{CStr, CString, c_char};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::Mutex;
use std::sync::mpsc::{self, SyncSender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{SigningKey, VerifyingKey};
use idevice::dvt::{
    location_simulation::LocationSimulationClient, remote_server::RemoteServerClient,
};
use idevice::pairing_file::PairingFile;
use idevice::remote_pairing::{
    RemotePairingClient, RpPairingFile, RpPairingSocket, connect_tls_psk_tunnel_native,
};
use idevice::rsd::RsdHandshake;
use idevice::services::core_device_proxy::CoreDeviceProxy;
use idevice::services::cryptexd::{self, Cryptex1Assets};
use idevice::services::heartbeat::HeartbeatClient;
use idevice::services::lockdown::LockdownClient;
use idevice::services::misagent::MisagentClient;
use idevice::{Idevice, IdeviceService};
use idevice::{ReadWrite, tcp::adapter::Adapter};
use serde::Deserialize;
use tokio::net::TcpStream;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

mod profile;
mod route_probe;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const DIAL_TIMEOUT: Duration = Duration::from_secs(5);
const PREPARATION_TIMEOUT: Duration = Duration::from_secs(180);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(20);
const HEARTBEAT_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_SETUP_BYTES: usize = 64 * 1024;
const MAX_LOCKDOWN_RECORD_BYTES: usize = 32 * 1024;
const PROFILE_OPERATION_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_COPIED_PROFILES: usize = 64;
const MAX_COPIED_PROFILE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Deserialize)]
struct SetupEnvelope {
    format: String,
    version: u32,
    device: Device,
    transport: Transport,
    pairing: Pairing,
    lockdown: Option<Lockdown>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Lockdown {
    pairing_record: String,
}

#[derive(Deserialize)]
struct Device {
    identifier: String,
}

#[derive(Deserialize)]
struct Transport {
    host: String,
    port: u16,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Pairing {
    identifier: String,
    private_key: String,
    public_key: String,
    peer_identifier: String,
    peer_public_key: String,
}

struct ValidatedSetup {
    endpoint: SocketAddr,
    expected_udid: String,
    peer_identifier: String,
    peer_public_key: [u8; 32],
    host_pairing: RpPairingFile,
    lockdown_pairing: Option<PairingFile>,
}

fn decode_key(label: &str, encoded: &str) -> Result<[u8; 32], String> {
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| format!("{label} must be base64"))?;
    bytes
        .try_into()
        .map_err(|_| format!("{label} must be exactly 32 bytes"))
}

fn describe_device_error(error: &idevice::IdeviceError) -> String {
    match error {
        idevice::IdeviceError::Socket(io_error) => {
            format!("socket {:?}: {io_error}", io_error.kind())
        }
        idevice::IdeviceError::LockdownSocket { phase, source } => {
            format!("{phase} socket {:?}: {source}", source.kind())
        }
        _ => error.to_string(),
    }
}

fn validate_lockdown_record(bytes: &[u8], expected_udid: &str) -> Result<PairingFile, String> {
    if bytes.is_empty() || bytes.len() > MAX_LOCKDOWN_RECORD_BYTES {
        return Err("lockdown pairing record must be 1 to 32768 bytes".into());
    }
    let value: plist::Value = plist::from_bytes(bytes)
        .map_err(|_| "lockdown pairing record is not a valid plist".to_string())?;
    let fields = value
        .as_dictionary()
        .ok_or_else(|| "lockdown pairing record must be a dictionary".to_string())?;
    const REQUIRED: [&str; 9] = [
        "DeviceCertificate",
        "HostCertificate",
        "HostPrivateKey",
        "RootCertificate",
        "HostID",
        "SystemBUID",
        "UDID",
        "RootPrivateKey",
        "WiFiMACAddress",
    ];
    if fields.len() != REQUIRED.len() || REQUIRED.iter().any(|name| !fields.contains_key(*name)) {
        return Err("lockdown pairing record fields differ from the minimal trusted export".into());
    }
    for name in [
        "DeviceCertificate",
        "HostCertificate",
        "HostPrivateKey",
        "RootCertificate",
    ] {
        match fields.get(name) {
            Some(plist::Value::Data(value)) if !value.is_empty() => {}
            _ => {
                return Err(format!(
                    "lockdown pairing record {name} must be nonempty binary data"
                ));
            }
        }
    }
    for name in ["HostID", "SystemBUID"] {
        match fields.get(name) {
            Some(plist::Value::String(value)) if !value.trim().is_empty() => {}
            _ => {
                return Err(format!(
                    "lockdown pairing record {name} must be a nonempty string"
                ));
            }
        }
    }
    if fields.get("UDID").and_then(plist::Value::as_string) != Some(expected_udid) {
        return Err("lockdown pairing record device identity differs from setup".into());
    }
    if !matches!(fields.get("RootPrivateKey"), Some(plist::Value::Data(value)) if value.is_empty())
    {
        return Err("lockdown pairing record must omit the root private key".into());
    }
    if !matches!(fields.get("WiFiMACAddress"), Some(plist::Value::String(_))) {
        return Err("lockdown pairing record WiFiMACAddress must be a string".into());
    }
    PairingFile::from_bytes(bytes).map_err(|_| {
        "lockdown pairing record contains an invalid certificate or host key".to_string()
    })
}

fn validate_setup(data: &[u8]) -> Result<ValidatedSetup, String> {
    if data.is_empty() || data.len() > MAX_SETUP_BYTES {
        return Err("setup document must be 1 to 65536 bytes".into());
    }
    let setup: SetupEnvelope =
        serde_json::from_slice(data).map_err(|e| format!("invalid setup JSON: {e}"))?;
    if setup.format != "gps.setup" || setup.version != 1 {
        return Err("unsupported setup format/version".into());
    }
    let peer_id = setup.pairing.peer_identifier.trim();
    let host_id = setup.pairing.identifier.trim();
    let udid = setup.device.identifier.trim();
    if peer_id.is_empty() || host_id.is_empty() || udid.is_empty() {
        return Err("setup identifiers cannot be empty".into());
    }

    // Do not resolve arbitrary DNS names or disclose pairing material to a
    // public endpoint. The setup exporter supplies the LocalDevVPN device IP.
    let ip: IpAddr = setup
        .transport
        .host
        .parse()
        .map_err(|_| "transport.host must be a numeric local IP address".to_string())?;
    let local = match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local(),
    };
    if !local || setup.transport.port == 0 {
        return Err("transport endpoint must be a local IP address and nonzero port".into());
    }

    let host_private = decode_key("pairing.privateKey", &setup.pairing.private_key)?;
    let host_public = decode_key("pairing.publicKey", &setup.pairing.public_key)?;
    let peer_public = decode_key("pairing.peerPublicKey", &setup.pairing.peer_public_key)?;
    let signing_key = SigningKey::from_bytes(&host_private);
    if signing_key.verifying_key().to_bytes() != host_public {
        return Err("pairing host private/public keys do not match".into());
    }
    VerifyingKey::from_bytes(&peer_public)
        .map_err(|_| "invalid pinned peer Ed25519 public key".to_string())?;

    let lockdown_pairing = if let Some(lockdown) = setup.lockdown {
        // The record contains the host's pairing private key. Decode it only
        // in memory and never include its bytes in an error or diagnostic.
        let bytes = STANDARD
            .decode(&lockdown.pairing_record)
            .map_err(|_| "lockdown.pairingRecord must be base64".to_string())?;
        Some(validate_lockdown_record(&bytes, udid)?)
    } else {
        None
    };

    Ok(ValidatedSetup {
        endpoint: SocketAddr::new(ip, setup.transport.port),
        expected_udid: udid.to_string(),
        peer_identifier: peer_id.to_string(),
        peer_public_key: peer_public,
        host_pairing: RpPairingFile {
            e_private_key: signing_key,
            e_public_key: VerifyingKey::from_bytes(&host_public)
                .map_err(|_| "invalid host Ed25519 public key".to_string())?,
            identifier: host_id.to_string(),
            alt_irk: None,
        },
        lockdown_pairing,
    })
}

fn validate_assets_directory(directory: *const c_char) -> Result<PathBuf, String> {
    if directory.is_null() {
        return Err("developer image assets directory is missing".into());
    }
    let text = unsafe { CStr::from_ptr(directory) }
        .to_str()
        .map_err(|_| "developer image assets directory must be UTF-8".to_string())?;
    if text.len() > 4096 || text.is_empty() {
        return Err("developer image assets directory path is empty or too long".into());
    }
    let path = PathBuf::from(text);
    if !path.is_absolute() {
        return Err("developer image assets directory must be an absolute path".into());
    }
    Ok(path)
}

fn verify_rsd_device(handshake: &RsdHandshake, expected_udid: &str) -> Result<(), String> {
    let rsd_udid = handshake
        .properties
        .get("UniqueDeviceID")
        .and_then(|value| value.as_string())
        .ok_or_else(|| "RSD handshake omitted UniqueDeviceID".to_string())?;
    if rsd_udid != expected_udid {
        return Err("RSD device identity differs from pinned setup".into());
    }
    Ok(())
}

async fn refresh_rsd_for_dvt(
    adapter: &mut idevice::tcp::handle::AdapterHandle,
    rsd_port: u16,
    expected_udid: &str,
) -> Result<RsdHandshake, String> {
    let dvt_name =
        <RemoteServerClient<Box<dyn ReadWrite>> as idevice::RsdService>::rsd_service_name();
    for attempt in 0..=5 {
        let stream = adapter
            .connect(rsd_port)
            .await
            .map_err(|e| format!("post-image RSD socket {:?}: {e}", e.kind()))?;
        let fresh = RsdHandshake::new(stream)
            .await
            .map_err(|e| format!("post-image RSD handshake: {}", describe_device_error(&e)))?;
        verify_rsd_device(&fresh, expected_udid)?;
        if fresh.services.contains_key(dvt_name.as_ref()) {
            return Ok(fresh);
        }
        if attempt < 5 {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
    Err("developer image mounted, but DVT service was not advertised after 5 seconds".into())
}

enum Command {
    Set(f64, f64, SyncSender<Result<(), String>>),
    Reset(SyncSender<Result<(), String>>),
    Shutdown,
}

/// Opaque session kept alive until `gps_native_disconnect`.
pub struct GPSNativeSession {
    sender: UnboundedSender<Command>,
    worker: Mutex<Option<JoinHandle<()>>>,
    finished: mpsc::Receiver<()>,
}

struct WorkerCompletion(SyncSender<()>);

impl Drop for WorkerCompletion {
    fn drop(&mut self) {
        let _ = self.0.send(());
    }
}

struct HeartbeatGuard {
    task: tokio::task::JoinHandle<()>,
    failure: tokio::sync::watch::Receiver<Option<String>>,
}

impl HeartbeatGuard {
    fn failure(&self) -> Option<String> {
        self.failure.borrow().clone()
    }
}

impl Drop for HeartbeatGuard {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn is_unreachable_socket_error(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::NetworkUnreachable
            | std::io::ErrorKind::HostUnreachable
            | std::io::ErrorKind::AddrNotAvailable
    )
}

enum ProxyFailure {
    Unavailable(String),
    Fatal(String),
}

async fn start_lockdown_heartbeat(
    lockdown: &mut LockdownClient,
    record: &PairingFile,
    ip: IpAddr,
) -> Result<HeartbeatGuard, ProxyFailure> {
    let (port, ssl) = lockdown
        .start_service(HeartbeatClient::service_name())
        .await
        .map_err(|e| {
            ProxyFailure::Fatal(format!(
                "heartbeat service start: {}",
                describe_device_error(&e)
            ))
        })?;
    let endpoint = SocketAddr::new(ip, port);
    let socket = tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(endpoint))
        .await
        .map_err(|_| ProxyFailure::Fatal("heartbeat socket timed out".into()))?
        .map_err(|e| ProxyFailure::Fatal(format!("heartbeat socket {:?}: {e}", e.kind())))?;
    socket.set_nodelay(true).map_err(|e| {
        ProxyFailure::Fatal(format!(
            "heartbeat socket low-latency setting {:?}: {e}",
            e.kind()
        ))
    })?;
    let mut device = Idevice::new(Box::new(socket), "GPS");
    if ssl {
        device.start_session(record, false).await.map_err(|e| {
            ProxyFailure::Fatal(format!(
                "heartbeat authenticated TLS: {}",
                describe_device_error(&e)
            ))
        })?;
    }
    let mut heartbeat = HeartbeatClient::new(device);
    let (status, failure) = tokio::sync::watch::channel(None);
    let task = tokio::spawn(async move {
        let mut wait_seconds = 60;
        loop {
            match heartbeat.get_marco(wait_seconds).await {
                Ok(interval) => {
                    wait_seconds = interval.saturating_mul(2).clamp(15, 120);
                    match tokio::time::timeout(HEARTBEAT_RESPONSE_TIMEOUT, heartbeat.send_polo())
                        .await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => {
                            let _ = status.send(Some(format!(
                                "heartbeat response: {}",
                                describe_device_error(&error)
                            )));
                            break;
                        }
                        Err(_) => {
                            let _ = status.send(Some("heartbeat response timed out".into()));
                            break;
                        }
                    }
                }
                Err(idevice::IdeviceError::Heartbeat(idevice::HeartbeatError::Timeout)) => {
                    // get_marco may have consumed part of a plist before its
                    // timeout cancels the read. Retrying on that socket would
                    // interpret the remaining bytes as a new frame.
                    let _ = status.send(Some("heartbeat stopped responding".into()));
                    break;
                }
                Err(error) => {
                    let _ = status.send(Some(format!(
                        "heartbeat: {}",
                        describe_device_error(&error)
                    )));
                    break;
                }
            }
        }
    });
    Ok(HeartbeatGuard { task, failure })
}

async fn authenticated_lockdown(setup: &ValidatedSetup) -> Result<LockdownClient, ProxyFailure> {
    let record = setup.lockdown_pairing.as_ref().ok_or_else(|| {
        ProxyFailure::Fatal("lockdown route has no trusted pairing record".into())
    })?;
    let endpoint = SocketAddr::new(setup.endpoint.ip(), LockdownClient::LOCKDOWND_PORT);
    let lockdown_stream = tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(endpoint))
        .await
        .map_err(|_| ProxyFailure::Unavailable("lockdown socket timed out".into()))?
        .map_err(|e| {
            let detail = format!("lockdown socket {:?}: {e}", e.kind());
            if is_unreachable_socket_error(&e) {
                ProxyFailure::Unavailable(detail)
            } else {
                ProxyFailure::Fatal(detail)
            }
        })?;
    lockdown_stream.set_nodelay(true).map_err(|e| {
        ProxyFailure::Fatal(format!(
            "lockdown socket low-latency setting {:?}: {e}",
            e.kind()
        ))
    })?;
    let mut lockdown = LockdownClient::new(Idevice::new(Box::new(lockdown_stream), "GPS"));
    lockdown.start_session_modern(record).await.map_err(|e| {
        let detail = format!(
            "lockdown authenticated session: {}",
            describe_device_error(&e)
        );
        if e.is_lockdown_transport_disconnect() {
            ProxyFailure::Unavailable(detail)
        } else {
            ProxyFailure::Fatal(detail)
        }
    })?;
    let lockdown_udid = lockdown
        .get_value(Some("UniqueDeviceID"), None)
        .await
        .map_err(|e| {
            ProxyFailure::Fatal(format!(
                "lockdown device identity: {}",
                describe_device_error(&e)
            ))
        })?;
    if lockdown_udid.as_string() != Some(setup.expected_udid.as_str()) {
        return Err(ProxyFailure::Fatal(
            "lockdown device identity differs from pinned setup".into(),
        ));
    }

    Ok(lockdown)
}

async fn core_device_proxy_tunnel(
    setup: &ValidatedSetup,
) -> Result<
    (
        idevice::tcp::handle::AdapterHandle,
        u16,
        LockdownClient,
        HeartbeatGuard,
    ),
    ProxyFailure,
> {
    let record = setup.lockdown_pairing.as_ref().ok_or_else(|| {
        ProxyFailure::Fatal("lockdown route has no trusted pairing record".into())
    })?;
    let mut lockdown = authenticated_lockdown(setup).await?;
    let heartbeat = start_lockdown_heartbeat(&mut lockdown, record, setup.endpoint.ip()).await?;

    let (service_port, service_ssl) = lockdown
        .start_service(CoreDeviceProxy::service_name())
        .await
        .map_err(|e| {
            ProxyFailure::Fatal(format!(
                "CoreDeviceProxy service start: {}",
                describe_device_error(&e)
            ))
        })?;
    let service_endpoint = SocketAddr::new(setup.endpoint.ip(), service_port);
    let service_stream = tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(service_endpoint))
        .await
        .map_err(|_| ProxyFailure::Fatal("CoreDeviceProxy socket timed out".into()))?
        .map_err(|e| ProxyFailure::Fatal(format!("CoreDeviceProxy socket {:?}: {e}", e.kind())))?;
    service_stream.set_nodelay(true).map_err(|e| {
        ProxyFailure::Fatal(format!(
            "CoreDeviceProxy socket low-latency setting {:?}: {e}",
            e.kind()
        ))
    })?;
    let mut service = Idevice::new(Box::new(service_stream), "GPS");
    // StartService decides whether this particular service uses TLS. On some
    // devices CoreDeviceProxy is a plain CDTunnel after its authenticated
    // Lockdown launch. If TLS is offered, pin it to the paired device too.
    if service_ssl {
        service.start_session(record, false).await.map_err(|e| {
            ProxyFailure::Fatal(format!(
                "CoreDeviceProxy authenticated TLS: {}",
                describe_device_error(&e)
            ))
        })?;
    }
    let proxy = CoreDeviceProxy::new(service).await.map_err(|e| {
        ProxyFailure::Fatal(format!(
            "CoreDeviceProxy tunnel: {}",
            describe_device_error(&e)
        ))
    })?;
    let rsd_port = proxy.tunnel_info().server_rsd_port;
    if rsd_port == 0 {
        return Err(ProxyFailure::Fatal(
            "CoreDeviceProxy tunnel omitted the RSD port".into(),
        ));
    }
    let adapter = proxy
        .create_software_tunnel()
        .map_err(|e| {
            ProxyFailure::Fatal(format!(
                "CoreDeviceProxy software tunnel: {}",
                describe_device_error(&e)
            ))
        })?
        .to_async_handle();
    Ok((adapter, rsd_port, lockdown, heartbeat))
}

async fn remote_pairing_tunnel(
    setup: &mut ValidatedSetup,
) -> Result<(idevice::tcp::handle::AdapterHandle, u16), String> {
    let pair_stream = tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(setup.endpoint))
        .await
        .map_err(|_| "local VPN socket timed out".to_string())?
        .map_err(|e| format!("local VPN socket {:?}: {e}", e.kind()))?;
    pair_stream
        .set_nodelay(true)
        .map_err(|e| format!("local VPN socket low-latency setting {:?}: {e}", e.kind()))?;
    let mut pairing = RemotePairingClient::new(
        RpPairingSocket::new(pair_stream),
        &setup.host_pairing.identifier,
    );
    pairing
        .attempt_pair_verify()
        .await
        .map_err(|e| format!("pair-verify handshake: {}", describe_device_error(&e)))?;
    pairing
        .validate_pairing_strict(
            &mut setup.host_pairing,
            &setup.peer_identifier,
            &setup.peer_public_key,
        )
        .await
        .map_err(|e| format!("peer signature verification: {}", describe_device_error(&e)))?;

    let listener_port = pairing
        .create_tcp_listener()
        .await
        .map_err(|e| format!("tunnel listener: {}", describe_device_error(&e)))?;
    let tunnel_endpoint = SocketAddr::new(setup.endpoint.ip(), listener_port);
    let tunnel_stream = tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(tunnel_endpoint))
        .await
        .map_err(|_| "tunnel socket timed out".to_string())?
        .map_err(|e| format!("tunnel socket {:?}: {e}", e.kind()))?;
    tunnel_stream
        .set_nodelay(true)
        .map_err(|e| format!("tunnel socket low-latency setting {:?}: {e}", e.kind()))?;
    let tunnel = connect_tls_psk_tunnel_native(tunnel_stream, pairing.encryption_key())
        .await
        .map_err(|e| format!("TLS-PSK/CDTunnel: {}", describe_device_error(&e)))?;
    let client_ip: IpAddr = tunnel
        .info
        .client_address
        .parse()
        .map_err(|e| format!("tunnel client address: {e}"))?;
    let server_ip: IpAddr = tunnel
        .info
        .server_address
        .parse()
        .map_err(|e| format!("tunnel server address: {e}"))?;
    let rsd_port = tunnel.info.server_rsd_port;
    if rsd_port == 0 {
        return Err("tunnel omitted the RSD port".into());
    }
    let mtu = tunnel.info.mtu as usize;
    let mut adapter = Adapter::new(Box::new(tunnel.into_inner()), client_ip, server_ip);
    adapter.set_mss(mtu.saturating_sub(60));
    Ok((adapter.to_async_handle(), rsd_port))
}

async fn establish_authenticated_rsd(
    mut setup: ValidatedSetup,
) -> Result<
    (
        idevice::tcp::handle::AdapterHandle,
        u16,
        RsdHandshake,
        Option<LockdownClient>,
        Option<HeartbeatGuard>,
    ),
    String,
> {
    // An explicitly selected loopback address uses strict RemotePairing:
    // Our on-device loopback test was denied access to Lockdown before auth.
    // Other local endpoints prefer the trusted Lockdown/CoreDeviceProxy service
    // when a classic record exists. Fall back only if the
    // proxy's TCP endpoint is unavailable or its classic session transport
    // closes. Never mask a certificate, device denial, identity, or protocol
    // failure; the alternate RPPairing path performs its own strict check.
    let prefer_proxy = setup.lockdown_pairing.is_some() && !setup.endpoint.ip().is_loopback();
    let (mut adapter, rsd_port, lockdown, heartbeat) = match prefer_proxy {
        true => match core_device_proxy_tunnel(&setup).await {
            Ok((adapter, rsd_port, lockdown, heartbeat)) => {
                (adapter, rsd_port, Some(lockdown), Some(heartbeat))
            }
            Err(ProxyFailure::Fatal(error)) => return Err(error),
            Err(ProxyFailure::Unavailable(reason)) => {
                let (adapter, rsd_port) =
                    remote_pairing_tunnel(&mut setup).await.map_err(|error| {
                        format!("CoreDeviceProxy unavailable ({reason}); remote pairing: {error}")
                    })?;
                (adapter, rsd_port, None, None)
            }
        },
        false => {
            let (adapter, rsd_port) = remote_pairing_tunnel(&mut setup).await?;
            (adapter, rsd_port, None, None)
        }
    };
    let rsd_stream = adapter
        .connect(rsd_port)
        .await
        .map_err(|e| format!("RSD socket {:?}: {e}", e.kind()))?;
    let handshake = RsdHandshake::new(rsd_stream)
        .await
        .map_err(|e| format!("RSD handshake: {}", describe_device_error(&e)))?;
    verify_rsd_device(&handshake, &setup.expected_udid)?;
    Ok((adapter, rsd_port, handshake, lockdown, heartbeat))
}

async fn establish(
    setup: ValidatedSetup,
    assets_directory: Option<&Path>,
) -> Result<
    (
        idevice::tcp::handle::AdapterHandle,
        RsdHandshake,
        RemoteServerClient<Box<dyn ReadWrite>>,
        Option<LockdownClient>,
        Option<HeartbeatGuard>,
    ),
    String,
> {
    let expected_udid = setup.expected_udid.clone();
    let (mut adapter, rsd_port, mut handshake, lockdown, heartbeat) =
        establish_authenticated_rsd(setup).await?;
    if let Some(directory) = assets_directory {
        if ensure_developer_image(&mut adapter, &mut handshake, directory).await? {
            // The first RSD handshake captured its service table before the
            // developer image mounted. Refresh it to discover DVT's newly
            // advertised port. Briefly wait only for service publication;
            // handshake and device-identity errors fail immediately.
            handshake = refresh_rsd_for_dvt(&mut adapter, rsd_port, &expected_udid).await?;
        }
    }
    let mut server: RemoteServerClient<Box<dyn ReadWrite>> = handshake
        .connect(&mut adapter)
        .await
        .map_err(|e| format!("DVT service socket: {}", describe_device_error(&e)))?;
    server
        .read_message(0)
        .await
        .map_err(|e| format!("DVT greeting: {}", describe_device_error(&e)))?;
    Ok((adapter, handshake, server, lockdown, heartbeat))
}

async fn ensure_developer_image(
    adapter: &mut idevice::tcp::handle::AdapterHandle,
    handshake: &mut RsdHandshake,
    directory: &Path,
) -> Result<bool, String> {
    let installed = cryptexd::installed_ddi(adapter, handshake)
        .await
        .map_err(|error| format!("developer image status: {}", describe_device_error(&error)))?;
    if installed.is_some() {
        return Ok(false);
    }

    let assets = Cryptex1Assets::load(directory)
        .await
        .map_err(|error| format!("developer image assets: {}", describe_device_error(&error)))?;
    cryptexd::install_ddi(adapter, handshake, &assets)
        .await
        .map_err(|error| match &error {
            idevice::IdeviceError::ImageNotMounted => {
                "developer image mount verification: image was not mounted".into()
            }
            idevice::IdeviceError::Cryptexd(_) => format!(
                "developer image installation or mount: {}",
                describe_device_error(&error)
            ),
            _ => format!(
                "developer image preparation: {}",
                describe_device_error(&error)
            ),
        })?;
    Ok(true)
}

// Profile management deliberately stops at misagent. It never mounts a
// developer image, opens DVT, or sends a location command.
enum ProfileConnection {
    Classic {
        client: MisagentClient,
        _lockdown: LockdownClient,
    },
    Rsd {
        client: MisagentClient,
        _adapter: idevice::tcp::handle::AdapterHandle,
        _lockdown: Option<LockdownClient>,
        _heartbeat: Option<HeartbeatGuard>,
    },
}

impl ProfileConnection {
    fn client(&mut self) -> &mut MisagentClient {
        match self {
            Self::Classic { client, .. } | Self::Rsd { client, .. } => client,
        }
    }
}

async fn classic_profile_connection(
    setup: &ValidatedSetup,
) -> Result<ProfileConnection, ProxyFailure> {
    let record = setup.lockdown_pairing.as_ref().ok_or_else(|| {
        ProxyFailure::Fatal("lockdown route has no trusted pairing record".into())
    })?;
    let mut lockdown = authenticated_lockdown(setup).await?;
    let (port, ssl) = lockdown
        .start_service(MisagentClient::service_name())
        .await
        .map_err(|error| {
            if matches!(error, idevice::IdeviceError::ServiceNotFound) {
                ProxyFailure::Unavailable("misagent was not offered by Lockdown".into())
            } else {
                ProxyFailure::Fatal("misagent service start failed".into())
            }
        })?;
    let endpoint = SocketAddr::new(setup.endpoint.ip(), port);
    let socket = tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(endpoint))
        .await
        .map_err(|_| ProxyFailure::Unavailable("misagent socket timed out".into()))?
        .map_err(|error| {
            if is_unreachable_socket_error(&error) {
                ProxyFailure::Unavailable(format!("misagent socket {:?}", error.kind()))
            } else {
                ProxyFailure::Fatal(format!("misagent socket {:?}", error.kind()))
            }
        })?;
    socket
        .set_nodelay(true)
        .map_err(|_| ProxyFailure::Fatal("misagent socket configuration failed".into()))?;
    let mut device = Idevice::new(Box::new(socket), "GPS");
    if ssl {
        device
            .start_session(record, false)
            .await
            .map_err(|_| ProxyFailure::Fatal("misagent authenticated TLS failed".into()))?;
    }
    Ok(ProfileConnection::Classic {
        client: MisagentClient::new(device),
        _lockdown: lockdown,
    })
}

async fn profile_connection(setup: ValidatedSetup) -> Result<ProfileConnection, String> {
    let classic_unavailable = if setup.lockdown_pairing.is_some() {
        match classic_profile_connection(&setup).await {
            Ok(connection) => return Ok(connection),
            Err(ProxyFailure::Fatal(error)) => return Err(error),
            Err(ProxyFailure::Unavailable(error)) => Some(error),
        }
    } else {
        None
    };
    let (mut adapter, _, mut handshake, lockdown, heartbeat) =
        establish_authenticated_rsd(setup).await.map_err(|error| {
            classic_unavailable
                .map(|reason| format!("classic misagent unavailable ({reason}); RSD: {error}"))
                .unwrap_or(error)
        })?;
    let client: MisagentClient = handshake
        .connect(&mut adapter)
        .await
        .map_err(|_| "RSD misagent connection failed".to_string())?;
    Ok(ProfileConnection::Rsd {
        client,
        _adapter: adapter,
        _lockdown: lockdown,
        _heartbeat: heartbeat,
    })
}

async fn copy_profiles_from_device(
    connection: &mut ProfileConnection,
) -> Result<Vec<Vec<u8>>, String> {
    let profiles = connection
        .client()
        .copy_all()
        .await
        .map_err(|_| "misagent profile readback failed".to_string())?;
    if profiles.len() > MAX_COPIED_PROFILES
        || profiles
            .iter()
            .try_fold(0usize, |total, profile| total.checked_add(profile.len()))
            .is_none_or(|total| total > MAX_COPIED_PROFILE_BYTES)
    {
        return Err("misagent returned too many profile bytes".into());
    }
    Ok(profiles)
}

async fn install_profile(setup: ValidatedSetup, profile: Vec<u8>) -> Result<(), String> {
    profile::validate_profile(&profile, &setup.expected_udid)?;
    let mut connection = profile_connection(setup).await?;
    connection
        .client()
        .install(profile.clone())
        .await
        .map_err(|_| "misagent rejected the profile installation".to_string())?;
    let readback = copy_profiles_from_device(&mut connection).await?;
    if !profile::confirms_readback(&profile, &readback) {
        return Err("installed profile was absent from misagent readback".into());
    }
    Ok(())
}

async fn worker_loop(
    setup: ValidatedSetup,
    assets_directory: Option<PathBuf>,
    mut receiver: UnboundedReceiver<Command>,
    ready: SyncSender<Result<(), String>>,
) {
    let connect_timeout = if assets_directory.is_some() {
        PREPARATION_TIMEOUT
    } else {
        CONNECT_TIMEOUT
    };
    let (adapter, handshake, mut server, lockdown, heartbeat) = match tokio::time::timeout(
        connect_timeout,
        establish(setup, assets_directory.as_deref()),
    )
    .await
    {
        Ok(Ok(connected)) => connected,
        Ok(Err(error)) => {
            let _ = ready.send(Err(error));
            return;
        }
        Err(_) => {
            let _ = ready.send(Err(if assets_directory.is_some() {
                "developer connection or image preparation timed out".into()
            } else {
                "connection timed out".into()
            }));
            return;
        }
    };
    let mut location =
        match tokio::time::timeout(COMMAND_TIMEOUT, LocationSimulationClient::new(&mut server))
            .await
        {
            Ok(Ok(location)) => location,
            Ok(Err(error)) => {
                let _ = ready.send(Err(format!(
                    "location service channel: {}",
                    describe_device_error(&error)
                )));
                return;
            }
            Err(_) => {
                let _ = ready.send(Err("location service channel timed out".into()));
                return;
            }
        };
    let _ = ready.send(Ok(()));

    while let Some(command) = receiver.recv().await {
        match command {
            Command::Set(latitude, longitude, reply) => {
                let result = if let Some(error) =
                    heartbeat.as_ref().and_then(HeartbeatGuard::failure)
                {
                    Err(error)
                } else {
                    tokio::time::timeout(COMMAND_TIMEOUT, location.set(latitude, longitude))
                        .await
                        .map_err(|_| "set command timed out".to_string())
                        .and_then(|result| {
                            result
                                .map_err(|e| format!("set command: {}", describe_device_error(&e)))
                        })
                };
                let _ = reply.send(result);
            }
            Command::Reset(reply) => {
                let result =
                    if let Some(error) = heartbeat.as_ref().and_then(HeartbeatGuard::failure) {
                        Err(error)
                    } else {
                        tokio::time::timeout(COMMAND_TIMEOUT, location.clear())
                            .await
                            .map_err(|_| "reset command timed out".to_string())
                            .and_then(|result| {
                                result.map_err(|e| {
                                    format!("reset command: {}", describe_device_error(&e))
                                })
                            })
                    };
                let _ = reply.send(result);
            }
            Command::Shutdown => break,
        }
    }
    drop(location);
    drop(server);
    drop(handshake);
    drop(adapter);
    drop(heartbeat);
    drop(lockdown);
}

fn put_error(out_error: *mut *mut c_char, message: &str) {
    if out_error.is_null() {
        return;
    }
    let sanitized = message.replace('\0', " ");
    let c_string = CString::new(sanitized).expect("NULs removed");
    unsafe { *out_error = c_string.into_raw() };
}

fn result_code(out_error: *mut *mut c_char, result: Result<(), String>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(message) => {
            put_error(out_error, &message);
            1
        }
    }
}

fn connect_native(
    setup_json: *const u8,
    setup_len: usize,
    assets_directory: Option<PathBuf>,
    out_session: *mut *mut GPSNativeSession,
    out_error: *mut *mut c_char,
) -> i32 {
    if !out_error.is_null() {
        unsafe { *out_error = ptr::null_mut() };
    }
    if out_session.is_null() || setup_json.is_null() {
        return result_code(out_error, Err("invalid setup/session pointer".into()));
    }
    unsafe { *out_session = ptr::null_mut() };
    if setup_len == 0 || setup_len > MAX_SETUP_BYTES {
        return result_code(out_error, Err("invalid setup length".into()));
    }
    let data = unsafe { std::slice::from_raw_parts(setup_json, setup_len) };
    let setup = match validate_setup(data) {
        Ok(setup) => setup,
        Err(error) => return result_code(out_error, Err(error)),
    };
    let (sender, receiver) = unbounded_channel();
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel(1);
    let connect_timeout = if assets_directory.is_some() {
        PREPARATION_TIMEOUT
    } else {
        CONNECT_TIMEOUT
    };
    let worker = thread::spawn(move || {
        let _completion = WorkerCompletion(finished_tx);
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build();
        match runtime {
            Ok(runtime) => {
                runtime.block_on(worker_loop(setup, assets_directory, receiver, ready_tx));
                runtime.shutdown_timeout(Duration::from_secs(2));
            }
            Err(error) => {
                let _ = ready_tx.send(Err(format!("native runtime: {error}")));
            }
        }
    });
    let ready = ready_rx.recv_timeout(connect_timeout + COMMAND_TIMEOUT + Duration::from_secs(5));
    match ready {
        Ok(Ok(())) => {
            unsafe {
                *out_session = Box::into_raw(Box::new(GPSNativeSession {
                    sender,
                    worker: Mutex::new(Some(worker)),
                    finished: finished_rx,
                }))
            };
            0
        }
        Ok(Err(error)) => {
            let _ = worker.join();
            result_code(out_error, Err(error))
        }
        Err(_) => result_code(
            out_error,
            Err("native connection worker did not respond".into()),
        ),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gps_native_connect(
    setup_json: *const u8,
    setup_len: usize,
    out_session: *mut *mut GPSNativeSession,
    out_error: *mut *mut c_char,
) -> i32 {
    connect_native(setup_json, setup_len, None, out_session, out_error)
}

#[unsafe(no_mangle)]
pub extern "C" fn gps_native_connect_with_assets(
    setup_json: *const u8,
    setup_len: usize,
    assets_directory: *const c_char,
    out_session: *mut *mut GPSNativeSession,
    out_error: *mut *mut c_char,
) -> i32 {
    if !out_error.is_null() {
        unsafe { *out_error = ptr::null_mut() };
    }
    if !out_session.is_null() {
        unsafe { *out_session = ptr::null_mut() };
    }
    let directory = match validate_assets_directory(assets_directory) {
        Ok(directory) => directory,
        Err(error) => return result_code(out_error, Err(error)),
    };
    connect_native(
        setup_json,
        setup_len,
        Some(directory),
        out_session,
        out_error,
    )
}

fn setup_from_c(setup_json: *const u8, setup_len: usize) -> Result<ValidatedSetup, String> {
    if setup_json.is_null() || setup_len == 0 || setup_len > MAX_SETUP_BYTES {
        return Err("invalid setup pointer or length".into());
    }
    let data = unsafe { std::slice::from_raw_parts(setup_json, setup_len) };
    validate_setup(data)
}

/// Opt-in, connect-only route comparison. No pairing or location protocol is sent.
#[unsafe(no_mangle)]
pub extern "C" fn gps_native_probe_local_route(
    setup_json: *const u8,
    setup_len: usize,
    out_json: *mut *mut c_char,
    out_error: *mut *mut c_char,
) -> i32 {
    if !out_error.is_null() {
        unsafe { *out_error = ptr::null_mut() };
    }
    if out_json.is_null() {
        return result_code(out_error, Err("missing route output pointer".into()));
    }
    unsafe { *out_json = ptr::null_mut() };
    let setup = match setup_from_c(setup_json, setup_len) {
        Ok(setup) => setup,
        Err(error) => return result_code(out_error, Err(error)),
    };
    let ip = match setup.endpoint.ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => {
            return result_code(
                out_error,
                Err("local VPN route check requires an IPv4 device endpoint".into()),
            );
        }
    };
    match route_probe::probe(ip, setup.endpoint.port()) {
        Ok(json) => {
            let output = CString::new(json).expect("fixed route JSON contains no NUL");
            unsafe { *out_json = output.into_raw() };
            0
        }
        Err(error) => result_code(out_error, Err(error)),
    }
}

fn run_profile_operation<T>(
    operation: impl std::future::Future<Output = Result<T, String>>,
) -> Result<T, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "profile transport runtime failed".to_string())?;
    let result = runtime.block_on(async {
        tokio::time::timeout(PROFILE_OPERATION_TIMEOUT, operation)
            .await
            .map_err(|_| "profile transport timed out".to_string())?
    });
    runtime.shutdown_timeout(Duration::from_secs(2));
    result
}

#[unsafe(no_mangle)]
pub extern "C" fn gps_native_install_profile(
    setup_json: *const u8,
    setup_len: usize,
    profile_bytes: *const u8,
    profile_len: usize,
    out_error: *mut *mut c_char,
) -> i32 {
    if !out_error.is_null() {
        unsafe { *out_error = ptr::null_mut() };
    }
    let setup = match setup_from_c(setup_json, setup_len) {
        Ok(setup) => setup,
        Err(error) => return result_code(out_error, Err(error)),
    };
    if profile_bytes.is_null() || profile_len == 0 || profile_len > profile::MAX_PROFILE_BYTES {
        return result_code(out_error, Err("invalid profile pointer or length".into()));
    }
    let profile = unsafe { std::slice::from_raw_parts(profile_bytes, profile_len) }.to_vec();
    // Do the cheap target checks before opening any socket or allocating a runtime.
    if let Err(error) = profile::validate_profile(&profile, &setup.expected_udid) {
        return result_code(out_error, Err(error));
    }
    result_code(
        out_error,
        run_profile_operation(install_profile(setup, profile)),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn gps_native_copy_profiles(
    setup_json: *const u8,
    setup_len: usize,
    out_json: *mut *mut c_char,
    out_error: *mut *mut c_char,
) -> i32 {
    if !out_error.is_null() {
        unsafe { *out_error = ptr::null_mut() };
    }
    if out_json.is_null() {
        return result_code(out_error, Err("missing profile output pointer".into()));
    }
    unsafe { *out_json = ptr::null_mut() };
    let setup = match setup_from_c(setup_json, setup_len) {
        Ok(setup) => setup,
        Err(error) => return result_code(out_error, Err(error)),
    };
    let result = run_profile_operation(async move {
        let mut connection = profile_connection(setup).await?;
        let profiles = copy_profiles_from_device(&mut connection).await?;
        let encoded: Vec<String> = profiles
            .iter()
            .map(|profile| STANDARD.encode(profile))
            .collect();
        serde_json::to_string(&encoded)
            .map_err(|_| "profile readback serialization failed".to_string())
    });
    match result {
        Ok(json) => {
            let output = CString::new(json).expect("base64 JSON contains no NUL");
            unsafe { *out_json = output.into_raw() };
            0
        }
        Err(error) => result_code(out_error, Err(error)),
    }
}

fn execute(
    session: *mut GPSNativeSession,
    out_error: *mut *mut c_char,
    make: impl FnOnce(SyncSender<Result<(), String>>) -> Command,
) -> i32 {
    if !out_error.is_null() {
        unsafe { *out_error = ptr::null_mut() };
    }
    if session.is_null() {
        return result_code(out_error, Err("no connected location session".into()));
    }
    let (reply_tx, reply_rx) = mpsc::sync_channel(1);
    let handle = unsafe { &*session };
    if handle.sender.send(make(reply_tx)).is_err() {
        return result_code(out_error, Err("location session is closed".into()));
    }
    let result = reply_rx.recv_timeout(COMMAND_TIMEOUT + Duration::from_secs(5));
    match result {
        Ok(result) => result_code(out_error, result),
        Err(_) => result_code(out_error, Err("location worker did not respond".into())),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gps_native_set(
    session: *mut GPSNativeSession,
    latitude: f64,
    longitude: f64,
    out_error: *mut *mut c_char,
) -> i32 {
    if !latitude.is_finite()
        || !longitude.is_finite()
        || !(-90.0..=90.0).contains(&latitude)
        || !(-180.0..=180.0).contains(&longitude)
    {
        if !out_error.is_null() {
            unsafe { *out_error = ptr::null_mut() };
        }
        return result_code(out_error, Err("coordinates out of range".into()));
    }
    execute(session, out_error, |reply| {
        Command::Set(latitude, longitude, reply)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn gps_native_reset(
    session: *mut GPSNativeSession,
    out_error: *mut *mut c_char,
) -> i32 {
    execute(session, out_error, Command::Reset)
}

#[unsafe(no_mangle)]
pub extern "C" fn gps_native_disconnect(session: *mut GPSNativeSession) {
    if session.is_null() {
        return;
    }
    let session = unsafe { Box::from_raw(session) };
    let _ = session.sender.send(Command::Shutdown);
    let worker_finished = session.finished.recv_timeout(SHUTDOWN_TIMEOUT).is_ok();
    if let Ok(mut worker) = session.worker.lock() {
        if let Some(worker) = worker.take() {
            if worker_finished {
                let _ = worker.join();
            }
            // If the worker has not stopped within the bound, dropping the
            // handle detaches it; the command channel closes with the session.
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gps_native_error_free(error: *mut c_char) {
    if !error.is_null() {
        let _ = unsafe { CString::from_raw(error) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    /// Run only against a user-authorized USB loopback forward to this phone's
    /// Lockdown port. No location command or private value is printed.
    #[test]
    #[ignore = "requires a private pair record and authorized USB loopback forward"]
    fn live_usb_lockdown_tls_probe() {
        let record_path = std::env::var_os("GPS_LOCKDOWN_PAIR_RECORD")
            .expect("GPS_LOCKDOWN_PAIR_RECORD must name the ignored private record");
        let port: u16 = std::env::var("GPS_LOCKDOWN_PROBE_PORT")
            .expect("GPS_LOCKDOWN_PROBE_PORT is required")
            .parse()
            .expect("GPS_LOCKDOWN_PROBE_PORT must be a port");
        let bytes = std::fs::read(record_path)
            .unwrap_or_else(|_| panic!("private pair record is unreadable"));
        let record = PairingFile::from_bytes(&bytes)
            .unwrap_or_else(|_| panic!("private pair record is invalid"));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Tokio runtime failed");
        runtime.block_on(async {
            let endpoint = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), port);
            let socket = tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(endpoint))
                .await
                .expect("Lockdown TCP dial timed out")
                .unwrap_or_else(|error| panic!("Lockdown TCP dial {:?}", error.kind()));
            println!("Lockdown probe: TCP connected");
            let mut lockdown = LockdownClient::new(Idevice::new(Box::new(socket), "GPS"));
            let session = tokio::time::timeout(
                Duration::from_secs(15),
                lockdown.start_session_modern(&record),
            )
            .await
            .expect("Lockdown session timed out");
            match session {
                Ok(_) => println!("Lockdown probe: pinned TLS established"),
                Err(idevice::IdeviceError::LockdownSocket { phase, source }) => {
                    panic!("Lockdown {phase}: socket {:?}", source.kind())
                }
                Err(error) => panic!("Lockdown session: error category {}", error.code()),
            }
            let identity = tokio::time::timeout(
                Duration::from_secs(10),
                lockdown.get_value(Some("UniqueDeviceID"), None),
            )
            .await
            .expect("Lockdown encrypted identity read timed out")
            .unwrap_or_else(|error| {
                panic!(
                    "Lockdown encrypted identity: error category {}",
                    error.code()
                )
            });
            assert!(
                identity.as_string() == record.udid.as_deref(),
                "Lockdown encrypted identity differs from private pair record"
            );
            println!("Lockdown probe: encrypted identity matched");
        });
    }

    #[test]
    fn rejects_missing_peer_pin() {
        let setup = br#"{"format":"gps.setup","version":1,"device":{"identifier":"TEST"},"transport":{"host":"10.7.0.1","port":49152},"pairing":{"identifier":"host","privateKey":"","publicKey":"","peerIdentifier":"TEST","peerPublicKey":""}}"#;
        assert!(validate_setup(setup).err().unwrap().contains("privateKey"));
    }

    #[test]
    fn socket_errors_include_underlying_kind_and_message() {
        let error = idevice::IdeviceError::Socket(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "connection reset by peer",
        ));
        let message = describe_device_error(&error);
        assert!(message.contains("ConnectionReset"));
        assert!(message.contains("connection reset by peer"));
    }

    #[test]
    fn assets_directory_must_be_absolute() {
        assert!(validate_assets_directory(ptr::null()).is_err());
        let relative = CString::new("GPSDeveloperImage").unwrap();
        assert!(validate_assets_directory(relative.as_ptr()).is_err());
        let absolute = CString::new("/var/mobile/Containers/Data/GPSDeveloperImage").unwrap();
        assert_eq!(
            validate_assets_directory(absolute.as_ptr()).unwrap(),
            PathBuf::from("/var/mobile/Containers/Data/GPSDeveloperImage"),
        );
    }

    #[test]
    fn disconnect_waits_for_worker_completion() {
        let (sender, mut receiver) = unbounded_channel();
        let (finished_tx, finished_rx) = mpsc::sync_channel(1);
        let stopped = Arc::new(AtomicBool::new(false));
        let worker_stopped = Arc::clone(&stopped);
        let worker = thread::spawn(move || {
            let _completion = WorkerCompletion(finished_tx);
            assert!(matches!(receiver.blocking_recv(), Some(Command::Shutdown)));
            worker_stopped.store(true, Ordering::SeqCst);
        });
        let session = Box::new(GPSNativeSession {
            sender,
            worker: Mutex::new(Some(worker)),
            finished: finished_rx,
        });
        gps_native_disconnect(Box::into_raw(session));
        assert!(stopped.load(Ordering::SeqCst));
    }

    #[test]
    fn rejects_public_endpoint() {
        let setup = br#"{"format":"gps.setup","version":1,"device":{"identifier":"TEST"},"transport":{"host":"8.8.8.8","port":49152},"pairing":{"identifier":"host","privateKey":"","publicKey":"","peerIdentifier":"TEST","peerPublicKey":""}}"#;
        assert!(validate_setup(setup).err().unwrap().contains("local IP"));
    }

    #[test]
    fn accepts_pinned_setup_with_matching_host_key() {
        let host_key = SigningKey::from_bytes(&[4u8; 32]);
        let peer_key = SigningKey::from_bytes(&[5u8; 32]);
        let setup = serde_json::json!({
            "format": "gps.setup",
            "version": 1,
            "device": { "identifier": "TEST" },
            "transport": { "host": "10.7.0.1", "port": 49152 },
            "pairing": {
                "identifier": "host-id",
                "privateKey": STANDARD.encode(host_key.to_bytes()),
                "publicKey": STANDARD.encode(host_key.verifying_key().to_bytes()),
                "peerIdentifier": "SIGNED-M6-PAIRING-ID",
                "peerPublicKey": STANDARD.encode(peer_key.verifying_key().to_bytes())
            }
        });
        let parsed = validate_setup(setup.to_string().as_bytes()).ok().unwrap();
        assert_eq!(parsed.endpoint.to_string(), "10.7.0.1:49152");
        assert_eq!(parsed.expected_udid, "TEST");
        assert_eq!(parsed.peer_identifier, "SIGNED-M6-PAIRING-ID");
    }

    #[test]
    fn lockdown_fallback_only_selects_transport_unreachable_errors() {
        assert!(is_unreachable_socket_error(&std::io::Error::from(
            std::io::ErrorKind::ConnectionRefused,
        )));
        assert!(is_unreachable_socket_error(&std::io::Error::from(
            std::io::ErrorKind::NetworkUnreachable,
        )));
        assert!(!is_unreachable_socket_error(&std::io::Error::from(
            std::io::ErrorKind::PermissionDenied,
        )));
        assert!(!is_unreachable_socket_error(&std::io::Error::from(
            std::io::ErrorKind::ConnectionReset,
        )));
    }

    #[test]
    fn lockdown_session_fallback_only_selects_transport_disconnects() {
        for kind in [
            std::io::ErrorKind::BrokenPipe,
            std::io::ErrorKind::ConnectionReset,
            std::io::ErrorKind::UnexpectedEof,
        ] {
            let error = idevice::IdeviceError::LockdownSocket {
                phase: "StartSession reply",
                source: std::io::Error::from(kind),
            };
            assert!(error.is_lockdown_transport_disconnect());
        }
        let protocol_error = idevice::IdeviceError::UnexpectedResponse(
            "missing EnableSessionSSL in StartSession response".into(),
        );
        assert!(!protocol_error.is_lockdown_transport_disconnect());
        assert!(!idevice::IdeviceError::InvalidHostID.is_lockdown_transport_disconnect());
        let ordinary_socket = idevice::IdeviceError::Socket(std::io::Error::from(
            std::io::ErrorKind::ConnectionReset,
        ));
        assert!(!ordinary_socket.is_lockdown_transport_disconnect());
        let non_retryable_io = idevice::IdeviceError::LockdownSocket {
            phase: "TLS handshake",
            source: std::io::Error::from(std::io::ErrorKind::InvalidData),
        };
        assert!(!non_retryable_io.is_lockdown_transport_disconnect());
    }

    #[test]
    fn rejects_oversized_or_unparseable_lockdown_records() {
        let host_key = SigningKey::from_bytes(&[4u8; 32]);
        let peer_key = SigningKey::from_bytes(&[5u8; 32]);
        let mut setup = serde_json::json!({
            "format": "gps.setup",
            "version": 1,
            "device": { "identifier": "TEST" },
            "transport": { "host": "10.7.0.1", "port": 49152 },
            "pairing": {
                "identifier": "host-id",
                "privateKey": STANDARD.encode(host_key.to_bytes()),
                "publicKey": STANDARD.encode(host_key.verifying_key().to_bytes()),
                "peerIdentifier": "signed-peer-id",
                "peerPublicKey": STANDARD.encode(peer_key.verifying_key().to_bytes())
            },
            "lockdown": { "pairingRecord": STANDARD.encode([0xAA]) }
        });
        let error = validate_setup(setup.to_string().as_bytes()).err().unwrap();
        assert!(error.contains("valid plist"));

        setup["lockdown"]["pairingRecord"] = STANDARD
            .encode(vec![0xAA; MAX_LOCKDOWN_RECORD_BYTES + 1])
            .into();
        let error = validate_setup(setup.to_string().as_bytes()).err().unwrap();
        assert!(error.contains("1 to 32768 bytes"));
    }

    #[test]
    fn lockdown_record_requires_minimal_fields_and_pinned_udid() {
        let mut fields = plist::Dictionary::new();
        for name in [
            "DeviceCertificate",
            "HostCertificate",
            "HostPrivateKey",
            "RootCertificate",
        ] {
            fields.insert(name.into(), plist::Value::Data(vec![1, 2, 3]));
        }
        for name in ["HostID", "SystemBUID"] {
            fields.insert(name.into(), plist::Value::String("host".into()));
        }
        fields.insert("UDID".into(), plist::Value::String("OTHER".into()));
        fields.insert("RootPrivateKey".into(), plist::Value::Data(vec![]));
        fields.insert("WiFiMACAddress".into(), plist::Value::String(String::new()));
        let encode = |fields: &plist::Dictionary| {
            let mut bytes = Vec::new();
            plist::to_writer_binary(&mut bytes, fields).unwrap();
            bytes
        };
        let error = validate_lockdown_record(&encode(&fields), "TEST")
            .err()
            .unwrap();
        assert!(error.contains("device identity differs"));

        fields.insert("UDID".into(), plist::Value::String("TEST".into()));
        fields.insert("EscrowBag".into(), plist::Value::Data(vec![1]));
        let error = validate_lockdown_record(&encode(&fields), "TEST")
            .err()
            .unwrap();
        assert!(error.contains("minimal trusted export"));

        fields.remove("EscrowBag");
        fields.insert("RootPrivateKey".into(), plist::Value::Data(vec![7]));
        let error = validate_lockdown_record(&encode(&fields), "TEST")
            .err()
            .unwrap();
        assert!(error.contains("omit the root private key"));
    }

    #[test]
    #[ignore = "requires a local private setup export; never commit that export"]
    fn local_enriched_setup_validates_if_supplied() {
        let path = std::env::var_os("GPS_NATIVE_SETUP_SMOKE_PATH")
            .expect("set GPS_NATIVE_SETUP_SMOKE_PATH to a private setup JSON path");
        let bytes = std::fs::read(path).unwrap();
        let setup = validate_setup(&bytes).unwrap();
        assert!(setup.lockdown_pairing.is_some());
    }
}

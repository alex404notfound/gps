// Lockdown certificates do not carry a public DNS name. Authenticate the
// exact device certificate from the trusted pairing record, then let rustls
// verify the server's TLS handshake signature with that certificate.

use rustls::{
    ClientConfig, DigitallySignedStruct,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject},
};
use std::sync::Arc;

use crate::{IdeviceError, pairing_file::PairingFile};

#[derive(Debug)]
pub struct PinnedDeviceVerifier {
    inner: Arc<WebPkiServerVerifier>,
    expected_certificate: CertificateDer<'static>,
}

impl PinnedDeviceVerifier {
    pub fn new(
        inner: Arc<WebPkiServerVerifier>,
        expected_certificate: CertificateDer<'static>,
    ) -> Self {
        Self {
            inner,
            expected_certificate,
        }
    }

    fn matches_pinned_certificate(&self, presented: &CertificateDer<'_>) -> bool {
        presented.as_ref() == self.expected_certificate.as_ref()
    }
}

impl ServerCertVerifier for PinnedDeviceVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if !self.matches_pinned_certificate(end_entity) {
            return Err(rustls::Error::General(
                "lockdown server certificate differs from paired device".into(),
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        if !self.matches_pinned_certificate(cert) {
            return Err(rustls::Error::General(
                "lockdown handshake certificate differs from paired device".into(),
            ));
        }
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        if !self.matches_pinned_certificate(cert) {
            return Err(rustls::Error::General(
                "lockdown handshake certificate differs from paired device".into(),
            ));
        }
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

pub fn create_client_config(pairing_file: &PairingFile) -> Result<ClientConfig, IdeviceError> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(pairing_file.root_certificate.clone())?;
    let private_key = PrivateKeyDer::from_pem_slice(&pairing_file.host_private_key)?;

    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store.clone())
        .with_client_auth_cert(vec![pairing_file.host_certificate.clone()], private_key)?;

    let inner = rustls::client::WebPkiServerVerifier::builder(Arc::new(root_store)).build()?;
    let verifier = Arc::new(PinnedDeviceVerifier::new(
        inner,
        pairing_file.device_certificate.clone(),
    ));
    config.dangerous().set_certificate_verifier(verifier);

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::{
        ClientConnection, RootCertStore, ServerConfig, ServerConnection, SupportedProtocolVersion,
        pki_types::PrivatePkcs8KeyDer,
        server::{ClientHello, ResolvesServerCert},
        sign::CertifiedKey,
        version,
    };

    const DEVICE_CERT: &[u8] = include_bytes!("../tests/fixtures/lockdown_tls/device.cert.der");
    const DEVICE_KEY: &[u8] = include_bytes!("../tests/fixtures/lockdown_tls/device.key.der");
    const OTHER_CERT: &[u8] = include_bytes!("../tests/fixtures/lockdown_tls/other.cert.der");
    const OTHER_KEY: &[u8] = include_bytes!("../tests/fixtures/lockdown_tls/other.key.der");

    #[derive(Debug)]
    struct FixedCert(Arc<CertifiedKey>);

    impl ResolvesServerCert for FixedCert {
        fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            Some(Arc::clone(&self.0))
        }
    }

    fn pinned_client(version: &'static SupportedProtocolVersion) -> ClientConnection {
        crate::ensure_default_crypto_provider();
        let paired_cert = CertificateDer::from(DEVICE_CERT.to_vec());
        let mut roots = RootCertStore::empty();
        roots.add(paired_cert.clone()).unwrap();
        let inner = WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .unwrap();
        let verifier = Arc::new(PinnedDeviceVerifier::new(inner, paired_cert));
        let config = ClientConfig::builder_with_protocol_versions(&[version])
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        ClientConnection::new(Arc::new(config), ServerName::try_from("Device").unwrap()).unwrap()
    }

    fn server(
        version: &'static SupportedProtocolVersion,
        certificate: &[u8],
        signing_key: &[u8],
    ) -> ServerConnection {
        crate::ensure_default_crypto_provider();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.to_vec()));
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key).unwrap();
        // A custom resolver deliberately permits a key that does not match
        // the certificate, simulating a forged handshake with the pinned leaf.
        let certified_key = CertifiedKey::new(
            vec![CertificateDer::from(certificate.to_vec())],
            signing_key,
        );
        let config = ServerConfig::builder_with_protocol_versions(&[version])
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(FixedCert(Arc::new(certified_key))));
        ServerConnection::new(Arc::new(config)).unwrap()
    }

    fn handshake(
        version: &'static SupportedProtocolVersion,
        certificate: &[u8],
        signing_key: &[u8],
    ) -> Result<(), rustls::Error> {
        let mut client = pinned_client(version);
        let mut server = server(version, certificate, signing_key);
        for _ in 0..16 {
            if client.wants_write() {
                let mut bytes = Vec::new();
                client.write_tls(&mut bytes).unwrap();
                server.read_tls(&mut bytes.as_slice()).unwrap();
                server.process_new_packets()?;
            }
            if server.wants_write() {
                let mut bytes = Vec::new();
                server.write_tls(&mut bytes).unwrap();
                client.read_tls(&mut bytes.as_slice()).unwrap();
                client.process_new_packets()?;
            }
            if !client.is_handshaking() && !server.is_handshaking() {
                return Ok(());
            }
        }
        panic!("TLS test handshake did not finish within 16 packet exchanges");
    }

    #[test]
    fn paired_leaf_with_matching_handshake_key_authenticates() {
        for version in [&version::TLS12, &version::TLS13] {
            handshake(version, DEVICE_CERT, DEVICE_KEY).unwrap();
        }
    }

    #[test]
    fn different_leaf_is_rejected_even_with_a_valid_handshake() {
        for version in [&version::TLS12, &version::TLS13] {
            assert!(handshake(version, OTHER_CERT, OTHER_KEY).is_err());
        }
    }

    #[test]
    fn pinned_leaf_with_forged_handshake_signature_is_rejected() {
        for version in [&version::TLS12, &version::TLS13] {
            assert!(handshake(version, DEVICE_CERT, OTHER_KEY).is_err());
        }
    }

    #[test]
    #[ignore = "requires a local trusted pairing record; never commit that record"]
    fn local_pairing_record_builds_pinned_tls_config() {
        let path = std::env::var_os("GPS_NATIVE_TRUSTED_PAIRING_PATH")
            .expect("set GPS_NATIVE_TRUSTED_PAIRING_PATH to a private plist path");
        let bytes = std::fs::read(path).unwrap();
        let record = PairingFile::from_bytes(&bytes).unwrap();
        create_client_config(&record).unwrap();
    }
}

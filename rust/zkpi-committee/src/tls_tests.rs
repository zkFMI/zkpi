//! Real TCP/TLS regression tests of the production context constructors.
use super::*;
use crate::key_management::{create_ca, issue_mutual_tls_certificate, write_tls_bundle};
use openssl::ssl::SslVersion;

struct Pki {
    _directory: tempfile::TempDir,
    server: (PathBuf, PathBuf, PathBuf),
    client: (PathBuf, PathBuf, PathBuf),
}

impl Pki {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let (ca_key, ca) = create_ca("pqc-test-ca", 1).unwrap();
        let bundle = |name| {
            let (key, certificate) =
                issue_mutual_tls_certificate(&ca_key, &ca, name, &[name], &["127.0.0.1"], 1)
                    .unwrap();
            write_tls_bundle(directory.path().join(name), name, &key, &certificate, &ca).unwrap()
        };
        let server = bundle("node-0");
        let client = bundle("client-0");
        Self {
            _directory: directory,
            server,
            client,
        }
    }

    fn server(&self, hybrid: bool) -> Arc<SslAcceptor> {
        let (key, cert, ca) = &self.server;
        if hybrid {
            return server_ssl_context(cert, key, ca).unwrap().acceptor;
        }
        let mut builder = SslAcceptor::mozilla_modern_v5(SslMethod::tls_server()).unwrap();
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        builder.set_groups_list("X25519").unwrap();
        builder.set_certificate_chain_file(cert).unwrap();
        builder
            .set_private_key(&load_owner_private_key(key).unwrap())
            .unwrap();
        builder.set_ca_file(ca).unwrap();
        builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        Arc::new(builder.build())
    }

    fn client(&self, hybrid: bool) -> Arc<SslConnector> {
        let (key, cert, ca) = &self.client;
        if hybrid {
            return client_ssl_context(cert, key, ca).unwrap().connector;
        }
        let mut builder = SslConnector::builder(SslMethod::tls_client()).unwrap();
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        builder.set_groups_list("X25519").unwrap();
        builder.set_certificate_chain_file(cert).unwrap();
        builder
            .set_private_key(&load_owner_private_key(key).unwrap())
            .unwrap();
        builder.set_ca_file(ca).unwrap();
        builder.set_verify(SslVerifyMode::PEER);
        Arc::new(builder.build())
    }
}

fn timeout(stream: &TcpStream) {
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
}

#[test]
fn hybrid_tls_real_tcp_reuses_connection_and_reconnects() {
    let pki = Pki::new();
    let acceptor = pki.server(true);
    let connector = pki.client(true);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        for _ in 0..2 {
            let (tcp, _) = listener.accept().unwrap();
            timeout(&tcp);
            let mut stream = acceptor.accept(tcp).unwrap();
            assert_eq!(stream.ssl().version_str(), "TLSv1.3");
            assert!(zkfmi_crypto::tls::certificate_uses_pqc_authentication(
                &stream.ssl().peer_certificate().unwrap()
            ));
            assert!(!stream.ssl().session_reused());
            for _ in 0..3 {
                let mut request = [0; 16];
                stream.read_exact(&mut request).unwrap();
                stream.write_all(&request).unwrap();
            }
        }
    });
    for connection in 0..2u8 {
        let tcp = TcpStream::connect(address).unwrap();
        timeout(&tcp);
        let mut stream = connector.connect("node-0", tcp).unwrap();
        assert_eq!(stream.ssl().version_str(), "TLSv1.3");
        assert!(zkfmi_crypto::tls::certificate_uses_pqc_authentication(
            &stream.ssl().peer_certificate().unwrap()
        ));
        assert!(!stream.ssl().session_reused());
        for sequence in 0..3u8 {
            let request = [connection + sequence; 16];
            stream.write_all(&request).unwrap();
            let mut response = [0; 16];
            stream.read_exact(&mut response).unwrap();
            assert_eq!(response, request);
        }
    }
    server.join().unwrap();
}

fn rejects_mixed_groups(server_hybrid: bool) {
    let pki = Pki::new();
    let acceptor = pki.server(server_hybrid);
    let connector = pki.client(!server_hybrid);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        timeout(&tcp);
        assert!(
            acceptor.accept(tcp).is_err(),
            "classical-only handshake accepted"
        );
    });
    let tcp = TcpStream::connect(address).unwrap();
    timeout(&tcp);
    assert!(
        connector.connect("node-0", tcp).is_err(),
        "classical-only handshake accepted"
    );
    server.join().unwrap();
}

#[test]
fn hybrid_server_rejects_classical_only_client() {
    rejects_mixed_groups(true);
}

#[test]
fn hybrid_client_rejects_classical_only_server() {
    rejects_mixed_groups(false);
}

// Invalid migration fixtures deliberately bypass the production issuer, which
// refuses classical keys. They remain otherwise valid X.509 chains.
fn migration_pki(ca_pqc: bool, server_pqc: bool, client_pqc: bool) -> Pki {
    use openssl::asn1::Asn1Time;
    use openssl::bn::{BigNum, MsbOption};
    use openssl::hash::MessageDigest;
    use openssl::pkey::{PKey, Private};
    use openssl::x509::extension::{
        BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
    };
    use openssl::x509::{X509NameBuilder, X509};
    fn key(pqc: bool) -> PKey<Private> {
        if pqc {
            zkfmi_crypto::tls::generate_authentication_key().unwrap()
        } else {
            PKey::generate_ed25519().unwrap()
        }
    }
    fn certificate(name: &str, key: &PKey<Private>, ca: Option<(&PKey<Private>, &X509)>) -> X509 {
        let mut subject = X509NameBuilder::new().unwrap();
        subject.append_entry_by_text("CN", name).unwrap();
        let subject = subject.build();
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        let mut serial = BigNum::new().unwrap();
        serial.rand(159, MsbOption::MAYBE_ZERO, false).unwrap();
        builder
            .set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();
        builder.set_subject_name(&subject).unwrap();
        builder
            .set_issuer_name(ca.map_or(subject.as_ref(), |(_, cert)| cert.subject_name()))
            .unwrap();
        builder.set_pubkey(key).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        if ca.is_none() {
            builder
                .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
                .unwrap();
            builder
                .append_extension(KeyUsage::new().critical().key_cert_sign().build().unwrap())
                .unwrap();
        } else {
            builder
                .append_extension(BasicConstraints::new().critical().build().unwrap())
                .unwrap();
            builder
                .append_extension(
                    KeyUsage::new()
                        .critical()
                        .digital_signature()
                        .build()
                        .unwrap(),
                )
                .unwrap();
            builder
                .append_extension(
                    ExtendedKeyUsage::new()
                        .server_auth()
                        .client_auth()
                        .build()
                        .unwrap(),
                )
                .unwrap();
            let san = SubjectAlternativeName::new()
                .dns(name)
                .build(&builder.x509v3_context(ca.map(|(_, cert)| cert.as_ref()), None))
                .unwrap();
            builder.append_extension(san).unwrap();
        }
        builder
            .sign(ca.map_or(key, |(key, _)| key), MessageDigest::null())
            .unwrap();
        builder.build()
    }
    let directory = tempfile::tempdir().unwrap();
    let ca_key = key(ca_pqc);
    let ca = certificate("migration-ca", &ca_key, None);
    let bundle = |name, pqc| {
        let key = key(pqc);
        let cert = certificate(name, &key, Some((&ca_key, &ca)));
        write_tls_bundle(directory.path().join(name), name, &key, &cert, &ca).unwrap()
    };
    let server = bundle("node-0", server_pqc);
    let client = bundle("client-0", client_pqc);
    Pki {
        _directory: directory,
        server,
        client,
    }
}

fn rejects_authentication(pki: Pki, hostname: &'static str) {
    let acceptor = pki.server(true);
    let connector = pki.client(true);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        timeout(&tcp);
        assert!(
            acceptor.accept(tcp).is_err(),
            "invalid authenticated peer accepted"
        );
    });
    let tcp = TcpStream::connect(address).unwrap();
    timeout(&tcp);
    // TLS 1.3 may deliver the server's client-certificate rejection only on
    // the first I/O after connect. No application response may be accepted.
    if let Ok(mut stream) = connector.connect(hostname, tcp) {
        let _ = stream.write_all(&[0]);
        assert!(stream.read_exact(&mut [0]).is_err());
    }
    server.join().unwrap();
}

#[test]
fn pqc_tls_rejects_classical_server_authentication() {
    rejects_authentication(migration_pki(true, false, true), "node-0");
}

#[test]
fn pqc_tls_rejects_classical_client_authentication() {
    rejects_authentication(migration_pki(true, true, false), "node-0");
}

#[test]
fn pqc_tls_rejects_classical_ca_even_with_pq_leaf_keys() {
    rejects_authentication(migration_pki(false, true, true), "node-0");
}

#[test]
fn pqc_tls_still_rejects_wrong_hostname() {
    rejects_authentication(Pki::new(), "another-node");
}

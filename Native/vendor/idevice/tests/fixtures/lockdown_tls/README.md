These certificates and keys were generated solely for local TLS verifier tests.
They are synthetic and are not from an iPhone, pairing record, or user account.

Each certificate is a self-signed X.509 v3 RSA leaf with serial zero and a
SHA-1 certificate signature, modeling legacy pairing certificate encoding.
The TLS handshake itself uses rustls's negotiated signature algorithm. The
tests present the paired leaf with both its matching key and the other leaf's
key to ensure that the handshake signature is checked independently of the
exact certificate pin. They also present a different leaf with its matching
key to exercise the pin.

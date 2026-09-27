# Local jktcp changes

This directory starts from the published `jktcp` 0.1.7 crate (MIT license).
The original crate archive has SHA-256
`4d3b9e59938be47d261173086c65a9352fe048951bc502109e7595b70b60cd98`,
matching the pre-vendor `Native/Cargo.lock` entry.

The iPhone tunnel passes a framed TLS stream to `Adapter`. A successful
`AsyncWrite::write_all` can leave an encrypted record buffered in that stream.
The adapter therefore flushes after each raw packet write, including the final
PSH carrying a location reset. PSH write/flush failures propagate to callers.

`StreamHandle::poll_flush` also waits until bytes blocked by the TCP send window
have left the adapter's local queue. This confirms local transport drain; it
does not assert that an iOS service executed the command or that physical GPS
has changed. Regression tests cover buffered records, flush errors, and
window-blocked writes.

The packet reader's 500 ms retry timer now runs only while protocol work is
pending. The handle already guards its 250 ms flush timer; the unconditional
reader timer had still been waking idle tunnels. Paused-clock tests verify
that an idle handle does not re-poll its transport over a virtual minute,
while unacknowledged data is retransmitted and quiet SYN handshakes time out.
Run the local, device-free tests with:

```sh
cargo test --locked --manifest-path Native/vendor/jktcp/Cargo.toml --lib -- --skip tests::local_tcp --skip tests::handle_speed
```

The two skipped upstream tests require a privileged TUN interface and manual
interaction. The remaining tests use synthetic in-memory transports.

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

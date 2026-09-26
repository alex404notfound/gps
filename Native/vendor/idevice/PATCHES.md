# Local idevice changes

This tree starts from [`jkcoxson/idevice`](https://github.com/jkcoxson/idevice)
commit `d32c8189c51c2789496b0768039419c3705498c3`. Its MIT license is in
`LICENSE.txt`. This is a source snapshot with local changes, not an unmodified
upstream release. `Native/README.md` describes the transport behavior.

The local changes include strict RemotePairing M2 peer-signature and TLS-PSK
Finished verification; buffered TLS writer corrections; pinned Lockdown TLS,
modern StartSession, and strict service parsing; heartbeat read bounds;
correlated DVT location replies; Cryptex persistence handling; and HTTPS
requirements for Apple personalization. The relevant source is under
`src/remote_pairing/`, `src/services/`, `src/sni.rs`, and `src/tss.rs`.

The pair-record OPACK decoder regression in `src/remote_pairing/opack.rs` now
uses a fully artificial encoded packet. Its account, serial, address, device
identifier, model, key bytes, and numeric ID are synthetic sentinels; the
`name` field still uses an OPACK back-reference to `model`. The companion
`src/remote_pairing/peer_device.rs` tests use an unmistakable
`TEST-DEVICE-...` identifier. These edits change test fixtures and expected
values only, not the protocol implementation.

The existing `opack.rs` header attributes its back-reference support to
[SideInstaller's copy of idevice](https://github.com/FrizzleM/SideInstaller/blob/main/rust-core/vendor/idevice/src/remote_pairing/opack.rs).
That provenance and its license compatibility need review before public
distribution; the upstream idevice MIT notice alone does not resolve it.

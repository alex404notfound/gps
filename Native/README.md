# Native developer-location transport

`libgpsnative.a` is an iOS static library exposing the C ABI in
[`include/GPSNative.h`](include/GPSNative.h). It uses the MIT-licensed
[`idevice` Rust library](https://github.com/jkcoxson/idevice) vendored from
commit `d32c8189c51c2789496b0768039419c3705498c3` under
`vendor/idevice`; its license is preserved there. Local patches add
`validate_pairing_strict`, which verifies the peer's encrypted M2 Ed25519
signature against a public key captured during trusted pairing; require a
matching TLS server Finished; and validate correlated DVT location replies.
The Lockdown route pins the exact device certificate from a trusted USB pair
record and verifies the server's TLS handshake signature; malformed
`StartService` replies are rejected.
The Cryptex request patch sends its own persistence value, and Apple TSS
personalization uses certificate-validated HTTPS without HTTP downgrade.
The TLS-PSK writer accepts buffered plaintext exactly once under socket
backpressure and drains it on flush or shutdown. The MIT-licensed
[`jktcp` 0.1.7](https://crates.io/crates/jktcp/0.1.7) TCP adapter is also
vendored under `vendor/jktcp`; its local patch flushes framed TLS packets and
propagates send errors. See `vendor/jktcp/PATCHES.md` for provenance.

The device and simulator archives were validated with Rust 1.98.1, Xcode
27.0, and its iOS 27 SDK. The current lockfile includes crates declaring a
minimum Rust version of 1.88.0; Rust 1.85 is not sufficient. Install the
`aarch64-apple-ios` and `aarch64-apple-ios-sim` targets, then build:

```sh
Native/build.sh device
Native/build.sh simulator
```

These produce `Native/build/iphoneos/libgpsnative.a` and
`Native/build/iphonesimulator/libgpsnative.a` respectively. Link the matching
archive in the Xcode target and expose `GPSNative.h` through the target's
bridging header. Calls block; Swift must call them off the main actor and
serialize use of a session. The `GPSNativeSession` pointer owns the open
location channel; `gps_native_disconnect` ends it. The caller owns the setup
JSON and must keep it in the Keychain. Native code neither persists it nor
logs private keys.

`gps_native_install_profile` and `gps_native_copy_profiles` are separate,
bounded misagent calls. They use the same authenticated device setup but do
not mount a developer image, open DVT, or issue location commands. The
installer accepts at most 2 MiB of CMS profile data. Before any connection,
it checks the embedded plist's app identifier for `app.gps.reconstruction`
and its device list for the paired iPhone; misagent enforces Apple's CMS
signature. Installation reports success only if CopyAll returns the exact
submitted CMS bytes. CopyAll returns a JSON array of base64 profiles through
an allocated C string; treat every profile as private data and release the
string with `gps_native_error_free`. The transport never removes profiles or
creates or revokes signing certificates. The Swift wrapper is
`App/Services/NativeProfileTransport.swift`.

The profile path prefers classic Lockdown `com.apple.misagent` with an
authenticated session and TLS when StartService requires it. A classic
transport/service availability failure can use the independently verified
RemotePairing/RSD `com.apple.misagent.shim.remote` path. Authentication,
device identity, and TLS failures remain terminal. Each profile network
operation has a 60-second bound plus at most two seconds for runtime teardown.
The user confirmed on-phone profile installation with exact readback and a
later expiration while USB was unplugged. Launching the app after its old
embedded profile expires remains untested.

`gps_native_probe_local_route` is an opt-in, connect-only check for the
configured LocalDevVPN device IP. It tests Lockdown port 62078 and the setup's
RemotePairing port with three-second bounds, reports only fixed outcome and
source-interface classes, and never sends authentication or location data.
Its UDP route preview is separate from the TCP socket source; a VPN-bound
comparison is attempted only when one point-to-point tunnel interface
advertises that exact device IP as its peer. The normal connection path does
not use this diagnostic to choose an interface.

Run the native unit tests with `cargo test --manifest-path Native/Cargo.toml
--lib`. The vendored protocol tests use `cargo test --manifest-path
Native/vendor/idevice/Cargo.toml --no-default-features --features
ring,remote_pairing,tunnel_tcp_stack,rsd,dvt,location_simulation,tcp,cryptexd,core_device_proxy,heartbeat,misagent
--lib`. The `--lib` flag excludes upstream documentation examples that still
contain placeholder crate names and do not compile. TLS regression tests use
synthetic certificates and keys documented under
`vendor/idevice/tests/fixtures/lockdown_tls/`; optional ignored smoke tests
can validate a private setup and pair record locally without contacting a
device. The ignored `live_usb_lockdown_tls_probe` takes a private record path
and a USB loopback-forward port from `GPS_LOCKDOWN_PAIR_RECORD` and
`GPS_LOCKDOWN_PROBE_PORT`. It only establishes pinned Lockdown TLS and checks
the encrypted device identity; it never sends a location command or prints
private values.

`gps_native_connect` accepts UTF-8 JSON in the `gps.setup` version 1 format:

```json
{
  "format": "gps.setup",
  "version": 1,
  "device": { "identifier": "trusted-device-udid", "name": "iPhone" },
  "transport": { "host": "10.7.0.1", "port": 49152 },
  "pairing": {
    "identifier": "host-pairing-identifier",
    "privateKey": "base64-32-byte-Ed25519-seed",
    "publicKey": "base64-32-byte-Ed25519-public-key",
    "peerIdentifier": "signed-M6-peer-identifier",
    "peerPublicKey": "base64-32-byte-Ed25519-public-key"
  },
  "lockdown": { "pairingRecord": "base64-minimal-classic-pairing-plist-optional" }
}
```

The host and port in this example are illustrative; setup export must supply
the actual LocalDevVPN device IP and reachable RPPairing control port. Native
rejects public IPs and DNS names. It never pairs automatically: missing or
incorrect peer pins fail before a tunnel or location channel can open. A
setup with `lockdown.pairingRecord` first tries classic Lockdown on the Device
IP at port 62078. It pins the device's exact certificate and TLS handshake
signature, verifies its UDID, runs a Marco/Polo heartbeat, and starts
CoreDeviceProxy through the trusted Lockdown service. The app's iOS 17.4+
path sends `StartSession` before any unauthenticated value probe and uses
modern pinned TLS; the vendored general-purpose API retains its legacy
version probe. A refused, unreachable, or timed-out initial Lockdown TCP dial,
or a BrokenPipe, ConnectionReset, or UnexpectedEof during classic session
setup, can fall back to independently pinned RPPairing. Explicit certificate
or signature rejection, device denial, malformed protocol responses, service
failures, and identity mismatches stop the connection. Existing setups without
a classic record use RPPairing directly.

The classic record must be a trusted USB export with exactly nine fields:
DeviceCertificate, HostCertificate, HostPrivateKey, RootCertificate, HostID,
SystemBUID, UDID, an empty Data RootPrivateKey, and a String WiFiMACAddress.
It is capped at 32 KiB decoded, and the app stores the whole setup in
Keychain. CoreDeviceProxy's service socket uses TLS when authenticated
Lockdown `StartService` requests it. On devices where that service runs plain
CDTunnel, the Lockdown control session is authenticated, but CDTunnel payloads
have no separate cryptographic server proof; they travel over the app's local
VPN route. The later RSD UDID check is not a cryptographic substitute for
service TLS. [Upstream idevice](https://github.com/jkcoxson/idevice) uses this
conditional service-TLS protocol, and its heartbeat service documents the
Marco/Polo keepalive requirement for network service connections.

The RPPairing route uses mutual pair verification and opens a TLS-PSK/CDTunnel
software TCP adapter. Both routes check the RSD `UniqueDeviceID` against the
pinned device, open DVT, and keep the location-simulation channel alive. `set`
waits for a correlated,
successful DVT acknowledgement. The modern `stopLocationSimulation` selector
does not send an acknowledgement, so `reset` reports that its command was sent
through the transport. Neither command independently reads physical location.
Local VPN TCP sockets request `TCP_NODELAY` to reduce small-command
latency; actual timing depends on the phone and network.

In current [LocalDevVPN address constants](https://github.com/jkcoxson/LocalDevVPN/blob/main/LocalDevVPN/Constants.swift),
**Device IP** defaults to `10.7.0.1/32`; **Tunnel IP** defaults to
`10.7.1.1/32`. Import the displayed Device IP, without `/32`, as
`transport.host`. [StikJIT uses](https://github.com/StikDebug/StikJIT/blob/main/Sources/JITSession.swift)
the Device IP and port `49152` for direct RPPairing. The LocalDevVPN values
are configurable, so inspect the phone's actual labels before export.

`device.identifier` is the trusted USB device UDID. `pairing.peerIdentifier`
is the distinct identifier signed in the M6 RemotePairing response; native
Pair-Verify compares that exact identifier and its pinned Ed25519 key. The
setup exporter binds both identities while talking to the trusted USB device,
and native checks the USB UDID again in the authenticated RSD handshake.

`gps_native_connect_with_assets` takes the same setup JSON plus a separate,
absolute path to the app's private `GPSDeveloperImage` directory. It checks for
an installed developer Cryptex **after** verifying the pinned RSD device ID.
If one is installed, it leaves it alone and does not read the assets. If none
is installed, it loads `BuildManifest.plist` and the four manifest-referenced
files from that directory, asks Apple TSS for a device-personalized ticket over
verified HTTPS, installs the image through on-device cryptexd, and verifies
that it mounted. It then refreshes RSD's service table, verifies the pinned
device ID again, and waits briefly for DVT to appear. It never rolls a nonce, uninstalls an image,
or reboots the phone. Image preparation can take up to 180 seconds. The old
`gps_native_connect` entry point remains available for already-mounted images.

The five Apple developer-image files must be copied into the app's private
Application Support directory before the phone is expected to prepare itself
after a reboot. Device operation still requires Developer Mode, an active
LocalDevVPN route, a valid setup document, and network access to Apple TSS if
the image is absent. The user confirmed connection after restarting the iPhone
with USB unplugged and Xcode closed, with Wi-Fi and LocalDevVPN on. A Wi-Fi-off,
cellular-only RPPairing attempt was refused before pairing, and a live
RPPairing tunnel broke during Wi-Fi-to-cellular handoff. The classic Lockdown
route requires a newly imported trusted USB pair record and phone validation;
it is not yet proven on this device. See the root validation document for the
tested behavior and remaining limits.

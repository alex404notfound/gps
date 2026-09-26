#ifndef GPS_NATIVE_H
#define GPS_NATIVE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct GPSNativeSession GPSNativeSession;

// All calls block and must run off the main actor. Success is 0; on failure,
// out_error receives an allocated UTF-8 string that gps_native_error_free owns.
// The caller owns a successful session and must disconnect it. Do not call
// disconnect concurrently with set or reset on the same session.
int32_t gps_native_connect(const uint8_t *setup_json,
                           size_t setup_len,
                           GPSNativeSession **out_session,
                           char **out_error);

// assets_directory is an absolute, app-owned Restore directory containing
// BuildManifest.plist and its four referenced Cryptex payload files. If the
// developer image is already mounted, this directory is not read. Otherwise
// the connection may block for up to roughly three minutes while the phone
// obtains its own Apple personalization ticket and mounts the image.
int32_t gps_native_connect_with_assets(const uint8_t *setup_json,
                                       size_t setup_len,
                                       const char *assets_directory,
                                       GPSNativeSession **out_session,
                                       char **out_error);

int32_t gps_native_set(GPSNativeSession *session,
                       double latitude,
                       double longitude,
                       char **out_error);

int32_t gps_native_reset(GPSNativeSession *session, char **out_error);

// A one-off, authenticated misagent operation. It never opens DVT or changes
// location. A profile must be an Apple CMS mobileprovision for this app and
// the paired device, at most 2 MiB. Installation succeeds only after exact
// profile bytes are returned by misagent CopyAll. No profiles are removed.
int32_t gps_native_install_profile(const uint8_t *setup_json,
                                   size_t setup_len,
                                   const uint8_t *profile_bytes,
                                   size_t profile_len,
                                   char **out_error);

// Returns a JSON array of base64 CMS profile bytes. This contains sensitive
// installed-profile data; keep it private and free with gps_native_error_free.
int32_t gps_native_copy_profiles(const uint8_t *setup_json,
                                 size_t setup_len,
                                 char **out_json,
                                 char **out_error);

// Opt-in route diagnostic. Connects only to the configured local device IP on
// Lockdown port 62078 and the configured RemotePairing port; it never sends
// pairing, profile, or location data. Returns sanitized JSON containing only
// a UDP route preview, each TCP socket's local-source interface class, and
// TCP outcomes (roughly 15 seconds worst case).
// Free out_json and out_error with gps_native_error_free.
int32_t gps_native_probe_local_route(const uint8_t *setup_json,
                                     size_t setup_len,
                                     char **out_json,
                                     char **out_error);

void gps_native_disconnect(GPSNativeSession *session);
void gps_native_error_free(char *error);

#ifdef __cplusplus
}
#endif

#endif

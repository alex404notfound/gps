# GPS Rebuilt

An experimental iPhone app for simulating GPS locations. Search for a place, pick a point on the map, or enter coordinates. Save favorites and reset the simulated location when finished.

Uses LocalDevVPN and an existing pairing setup to work without a connected Mac. Includes on-device signing renewal and Shortcuts support.

Signing refresh Shortcuts can run while the iPhone is locked. Open GPS once while
unlocked after updating so it can migrate the saved setup, Apple session, and
prepared profile. After a restart, unlock the phone once before automations run.
Keep LocalDevVPN on and configure the Shortcuts automation to Run Immediately.
Renewal secrets remain in the device-local Keychain using Apple's
[background-accessible protection](https://developer.apple.com/documentation/security/ksecattraccessibleafterfirstunlockthisdeviceonly).

Location monitoring uses coarse accuracy during an applied session and reduces
sampling further in the background or Low Power Mode. Reset verification uses
more accurate, unfiltered samples for at most 15 seconds, then stops monitoring.
The background session remains active so the developer connection can keep
working across app switches. This follows Apple's guidance for
[power-efficient background location](https://developer.apple.com/documentation/corelocation/cllocationmanager/pauseslocationupdatesautomatically).

Idle tunnels wait for network activity without periodic polling. Automatic
signing checks are scheduled no earlier than the profile's three-day renewal
window, retaining a 12-hour retry interval when renewal is already due. iOS
decides when background requests actually run. Battery savings need to be
measured on an iPhone with an active LocalDevVPN session.

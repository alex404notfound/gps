//! Bounded, structural preflight for an Apple CMS provisioning profile.
//! The device's misagent verifies the CMS signature when installing it. This
//! parser only ensures we never submit a different app or device's profile.

use plist::Value;

pub(super) const MAX_PROFILE_BYTES: usize = 2 * 1024 * 1024;
const TARGET_BUNDLE_ID: &str = "app.gps.reconstruction";
const SIGNED_DATA_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
const DATA_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];

struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
}

fn take_tlv<'a>(input: &mut &'a [u8]) -> Result<Tlv<'a>, String> {
    if input.len() < 2 {
        return Err("profile CMS has a truncated field".into());
    }
    let tag = input[0];
    let first_len = input[1];
    let mut header = 2usize;
    let len = if first_len & 0x80 == 0 {
        usize::from(first_len)
    } else {
        let count = usize::from(first_len & 0x7f);
        if count == 0 || count > 4 || input.len() < header + count || input[header] == 0 {
            return Err("profile CMS has an invalid length".into());
        }
        let mut value = 0usize;
        for byte in &input[header..header + count] {
            value = value
                .checked_mul(256)
                .and_then(|value| value.checked_add(usize::from(*byte)))
                .ok_or_else(|| "profile CMS length overflow".to_string())?;
        }
        if value < 128 {
            return Err("profile CMS has a noncanonical length".into());
        }
        header += count;
        value
    };
    if len > input.len() - header {
        return Err("profile CMS has a truncated value".into());
    }
    let field = Tlv {
        tag,
        value: &input[header..header + len],
    };
    *input = &input[header + len..];
    Ok(field)
}

fn required_tlv<'a>(input: &mut &'a [u8], tag: u8) -> Result<&'a [u8], String> {
    let field = take_tlv(input)?;
    if field.tag != tag {
        return Err("profile CMS has an unexpected field".into());
    }
    Ok(field.value)
}

fn extract_payload(profile: &[u8]) -> Result<&[u8], String> {
    let mut envelope = profile;
    let mut content = required_tlv(&mut envelope, 0x30)?;
    if !envelope.is_empty() || required_tlv(&mut content, 0x06)? != SIGNED_DATA_OID {
        return Err("profile is not CMS SignedData".into());
    }
    let mut signed_data_wrapper = required_tlv(&mut content, 0xa0)?;
    if !content.is_empty() {
        return Err("profile CMS has trailing content".into());
    }
    let mut signed_data = required_tlv(&mut signed_data_wrapper, 0x30)?;
    if !signed_data_wrapper.is_empty() {
        return Err("profile CMS has trailing SignedData".into());
    }
    required_tlv(&mut signed_data, 0x02)?; // version
    required_tlv(&mut signed_data, 0x31)?; // digestAlgorithms
    let mut encapsulated = required_tlv(&mut signed_data, 0x30)?;
    if required_tlv(&mut encapsulated, 0x06)? != DATA_OID {
        return Err("profile CMS has an unexpected payload type".into());
    }
    let mut payload_wrapper = required_tlv(&mut encapsulated, 0xa0)?;
    if !encapsulated.is_empty() {
        return Err("profile CMS has trailing payload fields".into());
    }
    let payload = required_tlv(&mut payload_wrapper, 0x04)?;
    if !payload_wrapper.is_empty() || payload.is_empty() || payload.len() > MAX_PROFILE_BYTES {
        return Err("profile CMS payload is invalid".into());
    }
    Ok(payload)
}

pub(super) fn validate_profile(profile: &[u8], expected_udid: &str) -> Result<(), String> {
    if profile.is_empty() || profile.len() > MAX_PROFILE_BYTES {
        return Err("profile must be 1 to 2097152 bytes".into());
    }
    let payload = extract_payload(profile)?;
    let value: Value = plist::from_bytes(payload)
        .map_err(|_| "profile CMS payload is not a valid plist".to_string())?;
    let dictionary = value
        .as_dictionary()
        .ok_or_else(|| "profile payload must be a dictionary".to_string())?;
    let app_id = dictionary
        .get("Entitlements")
        .and_then(Value::as_dictionary)
        .and_then(|entitlements| entitlements.get("application-identifier"))
        .and_then(Value::as_string)
        .ok_or_else(|| "profile omitted its application identifier".to_string())?;
    let suffix = format!(".{TARGET_BUNDLE_ID}");
    let prefix = app_id
        .strip_suffix(&suffix)
        .filter(|prefix| !prefix.is_empty() && !prefix.contains('.'))
        .ok_or_else(|| "profile targets a different application".to_string())?;
    if dictionary
        .get("TeamIdentifier")
        .and_then(Value::as_array)
        .is_some_and(|teams| !teams.iter().any(|team| team.as_string() == Some(prefix)))
    {
        return Err("profile team differs from its application identifier".into());
    }
    let devices = dictionary
        .get("ProvisionedDevices")
        .and_then(Value::as_array)
        .ok_or_else(|| "profile omitted its provisioned devices".to_string())?;
    if !devices
        .iter()
        .any(|device| device.as_string() == Some(expected_udid))
    {
        return Err("profile does not include the paired iPhone".into());
    }
    Ok(())
}

pub(super) fn confirms_readback(profile: &[u8], readback: &[Vec<u8>]) -> bool {
    readback.iter().any(|installed| installed == profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut output = vec![tag];
        if value.len() < 128 {
            output.push(value.len() as u8);
        } else {
            output.push(0x82);
            output.extend_from_slice(&(value.len() as u16).to_be_bytes());
        }
        output.extend_from_slice(value);
        output
    }

    fn signed_data(plist: Value) -> Vec<u8> {
        let mut payload = Vec::new();
        plist.to_writer_xml(&mut payload).unwrap();
        let mut encap = tlv(0x06, DATA_OID);
        encap.extend(tlv(0xa0, &tlv(0x04, &payload)));
        let mut signed = tlv(0x02, &[1]);
        signed.extend(tlv(0x31, &[]));
        signed.extend(tlv(0x30, &encap));
        let mut content = tlv(0x06, SIGNED_DATA_OID);
        content.extend(tlv(0xa0, &tlv(0x30, &signed)));
        tlv(0x30, &content)
    }

    fn profile(app_id: &str, devices: &[&str]) -> Vec<u8> {
        let mut entitlements = plist::Dictionary::new();
        entitlements.insert("application-identifier".into(), app_id.into());
        let mut payload = plist::Dictionary::new();
        payload.insert("Entitlements".into(), entitlements.into());
        payload.insert(
            "ProvisionedDevices".into(),
            Value::Array(devices.iter().map(|device| (*device).into()).collect()),
        );
        signed_data(Value::Dictionary(payload))
    }

    #[test]
    fn preflight_rejects_wrong_app_and_wrong_device() {
        let valid = profile("TEAM.app.gps.reconstruction", &["PHONE"]);
        assert!(validate_profile(&valid, "PHONE").is_ok());
        assert!(validate_profile(&valid, "OTHER").is_err());
        assert!(
            validate_profile(&profile("TEAM.app.gps.development", &["PHONE"]), "PHONE").is_err()
        );
        assert!(
            validate_profile(
                &profile("TEAM.other.app.gps.reconstruction", &["PHONE"]),
                "PHONE"
            )
            .is_err()
        );
    }

    #[test]
    fn preflight_rejects_bad_cms_and_oversize() {
        assert!(validate_profile(b"<plist></plist>", "PHONE").is_err());
        assert!(validate_profile(&vec![0; MAX_PROFILE_BYTES + 1], "PHONE").is_err());
        let mut valid = profile("TEAM.app.gps.reconstruction", &["PHONE"]);
        valid.push(0);
        assert!(validate_profile(&valid, "PHONE").is_err());
    }

    #[test]
    fn readback_requires_exact_installed_profile() {
        let valid = profile("TEAM.app.gps.reconstruction", &["PHONE"]);
        assert!(confirms_readback(&valid, &[vec![1], valid.clone()]));
        assert!(!confirms_readback(&valid, &[vec![1], vec![2]]));
    }

    #[test]
    #[ignore = "requires the ignored local build profile and private setup"]
    fn real_build_profile_preflight() {
        let profile = std::fs::read(std::env::var("GPS_TEST_PROFILE").unwrap()).unwrap();
        let setup = std::fs::read(std::env::var("GPS_TEST_SETUP").unwrap()).unwrap();
        let setup = super::super::validate_setup(&setup).unwrap();
        validate_profile(&profile, &setup.expected_udid).unwrap();
    }
}

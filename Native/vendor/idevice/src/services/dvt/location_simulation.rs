//! Location Simulation service client for iOS instruments protocol.
//!
//! This module abstracts simulating the device's location over
//! the remote server protocol. Note that a connection must be
//! maintained to keep location simulated.
//!
//! # Example
//! ```rust,no_run
//! #[tokio::main]
//! async fn main() -> Result<(), IdeviceError> {
//!     // Create base client (implementation specific)
//!     let mut client = RemoteServerClient::new(your_transport);
//!
//!     // Create process control client
//!     let mut process_control = ProcessControlClient::new(&mut client).await?;
//!
//!     // Launch an app
//!     let pid = process_control.launch_app(
//!         "com.example.app",
//!         None,       // Environment variables
//!         None,       // Arguments
//!         false,      // Start suspended
//!         true        // Kill existing
//!     ).await?;
//!     println!("Launched app with PID: {}", pid);
//!
//!     // Disable memory limits
//!     process_control.disable_memory_limit(pid).await?;
//!
//!     // Kill the app
//!     process_control.kill_app(pid).await?;
//!
//!     Ok(())
//! }
//! ```

use plist::Value;

use crate::{
    IdeviceError, ReadWrite,
    dvt::{
        message::{AuxValue, Message},
        remote_server::{Channel, RemoteServerClient},
    },
    obf,
};

/// A client for the location simulation service
#[derive(Debug)]
pub struct LocationSimulationClient<'a, R: ReadWrite> {
    /// The underlying channel used for communication
    channel: Channel<'a, R>,
}

fn require_void_reply(reply: Message) -> Result<(), IdeviceError> {
    match reply.payload_header.message_type() {
        0 | 3 if reply.data.is_none() && reply.aux.is_none() => Ok(()),
        4 => Err(IdeviceError::InternalError(format!(
            "location service returned a DTX error: {:?}", reply.data
        ))),
        kind => Err(IdeviceError::UnexpectedResponse(format!(
            "unexpected location service reply type {kind} or payload: {:?}", reply.data
        ))),
    }
}

impl<'a, R: ReadWrite> LocationSimulationClient<'a, R> {
    /// Opens a new channel on the remote server client for location simulation
    ///
    /// # Arguments
    /// * `client` - The remote server client to connect with
    ///
    /// # Returns
    /// The client on success, IdeviceError on failure
    pub async fn new(client: &'a mut RemoteServerClient<R>) -> Result<Self, IdeviceError> {
        let channel = client
            .make_channel(obf!(
                "com.apple.instruments.server.services.LocationSimulation"
            ))
            .await?; // Drop `&mut client` before continuing

        Ok(Self { channel })
    }

    /// Clears the set GPS location
    pub async fn clear(&mut self) -> Result<(), IdeviceError> {
        let method = Value::String("stopLocationSimulation".into());
        // The modern service does not send an acknowledgement for this selector.
        // A successful return means the command reached the transport; it does
        // not prove the phone has restored its physical location.
        self.channel.call_method(Some(method), None, false).await
    }

    /// Sets the GPS location
    ///
    /// # Arguments
    /// * `latitude` - The f64 latitude value
    /// * `longitude` - The f64 longitude value
    ///
    /// # Errors
    /// Returns an IdeviceError on failure
    pub async fn set(&mut self, latitude: f64, longitude: f64) -> Result<(), IdeviceError> {
        let method = Value::String("simulateLocationWithLatitude:longitude:".into());

        let reply = self.channel
            .call_method_with_reply(
                Some(method),
                Some(vec![
                    AuxValue::archived_value(latitude),
                    AuxValue::archived_value(longitude),
                ]),
            )
            .await?;
        require_void_reply(reply)
    }
}

#[cfg(test)]
mod gps_location_reply_tests {
    use super::*;
    use crate::dvt::message::{MessageHeader, PayloadHeader};

    fn response(payload_header: PayloadHeader, data: Option<Value>) -> Message {
        Message::new(MessageHeader::new(0, 1, 1, 1, 1, false), payload_header, None, data)
    }

    #[test]
    fn accepts_only_empty_acknowledgement() {
        assert!(require_void_reply(response(PayloadHeader::new(), None)).is_ok());
        assert!(require_void_reply(response(
            PayloadHeader::new(), Some(Value::String("failure".into()))
        )).is_err());
        assert!(require_void_reply(response(PayloadHeader::method_invocation(), None)).is_err());
    }

    #[tokio::test]
    async fn rejects_correlated_dtx_error_reply() {
        let mut wire = response(
            PayloadHeader::new(),
            Some(Value::String("location request rejected".into())),
        ).serialize();
        wire[32] = 4; // DTX ERROR, not an OK acknowledgement.
        let parsed = Message::from_reader(&mut wire.as_slice()).await.unwrap();
        assert!(require_void_reply(parsed).is_err());
    }
}

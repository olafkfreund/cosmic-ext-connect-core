//! Lock plugin
//!
//! Allows locking/unlocking the remote device's screen.
//! Reports lock status and accepts lock/unlock commands.

use crate::protocol::Packet;
use crate::error::Result;
use serde_json::json;

/// Lock status packet type
pub const PACKET_TYPE_LOCK: &str = "cconnect.lock";
/// Lock request packet type
pub const PACKET_TYPE_LOCK_REQUEST: &str = "cconnect.lock.request";

/// Create a lock status packet
pub fn create_lock_packet(is_locked: bool) -> Result<Packet> {
    Ok(Packet::new(PACKET_TYPE_LOCK, json!({"isLocked": is_locked})))
}

/// Create a lock request packet to set lock state
pub fn create_lock_request(set_locked: bool) -> Result<Packet> {
    Ok(Packet::new(PACKET_TYPE_LOCK_REQUEST, json!({"setLocked": set_locked})))
}

/// Create a lock status request (query current state)
pub fn create_lock_status_request() -> Result<Packet> {
    Ok(Packet::new(PACKET_TYPE_LOCK_REQUEST, json!({"requestLocked": true})))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_lock_packet_locked() {
        let packet = create_lock_packet(true).unwrap();
        assert_eq!(packet.packet_type, "cconnect.lock");
        assert_eq!(packet.body["isLocked"], true);
    }

    #[test]
    fn test_create_lock_packet_unlocked() {
        let packet = create_lock_packet(false).unwrap();
        assert_eq!(packet.body["isLocked"], false);
    }

    #[test]
    fn test_create_lock_request() {
        let packet = create_lock_request(true).unwrap();
        assert_eq!(packet.packet_type, "cconnect.lock.request");
        assert_eq!(packet.body["setLocked"], true);
    }

    #[test]
    fn test_create_lock_status_request() {
        let packet = create_lock_status_request().unwrap();
        assert_eq!(packet.packet_type, "cconnect.lock.request");
        assert_eq!(packet.body["requestLocked"], true);
    }
}

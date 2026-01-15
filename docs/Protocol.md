# KDE Connect Protocol Documentation

## Overview

The KDE Connect protocol is a device-to-device communication protocol designed for seamless integration between computers, smartphones, and other devices. This implementation supports **protocol version 7**.

## Protocol Specification

### Protocol Version

Current implementation: **Version 7**

Version history:
- Version 7: Current standard (2019+)
- Version 6: Legacy support
- Version 5 and below: Not supported

### Transport Layers

The protocol uses two transport mechanisms:

1. **UDP (Discovery)**
   - Port: 1716
   - Purpose: Device discovery via broadcast
   - Format: JSON identity packets with newline terminator

2. **TCP (Data Transfer)**
   - Port: Negotiated during discovery (typically 1716-1764)
   - Purpose: Paired device communication
   - Security: TLS-encrypted after pairing

## Packet Format

### Base Packet Structure

All KDE Connect packets are JSON objects terminated with a single newline character (`\n`).

```json
{
  "id": 1234567890123,
  "type": "kdeconnect.plugin.action",
  "body": {
    "key": "value"
  }
}
\n
```

### Required Fields

- **id** (number or string): UNIX timestamp in milliseconds
- **type** (string): Packet type identifier
- **body** (object): Plugin-specific parameters

### Optional Fields

- **payloadSize** (number): Size of payload data in bytes
  - `-1` indicates indefinite stream
  - `0` indicates no payload
  - Positive values indicate exact byte count

- **payloadTransferInfo** (object): Payload transfer negotiation parameters
  - Used for file transfers and streaming
  - Contains port numbers and transfer modes

### Packet Type Naming Convention

Format: `kdeconnect.<plugin>[.<action>]`

Examples:
- `kdeconnect.identity` - Device identity announcement
- `kdeconnect.ping` - Simple ping packet
- `kdeconnect.battery` - Battery status update
- `kdeconnect.battery.request` - Request battery status
- `kdeconnect.mpris` - Media player status
- `kdeconnect.mpris.request` - Request media player info
- `kdeconnect.share` - File sharing
- `kdeconnect.notification` - Notification sync

## Identity Packet

### Purpose

The identity packet announces a device's presence and capabilities. It's used during discovery and pairing.

### Structure

```json
{
  "id": 1234567890123,
  "type": "kdeconnect.identity",
  "body": {
    "deviceId": "abc123_def456_ghi789_jkl012",
    "deviceName": "My Computer",
    "protocolVersion": 7,
    "deviceType": "desktop",
    "tcpPort": 1716,
    "incomingCapabilities": [
      "kdeconnect.battery",
      "kdeconnect.ping",
      "kdeconnect.share.request"
    ],
    "outgoingCapabilities": [
      "kdeconnect.battery.request",
      "kdeconnect.ping",
      "kdeconnect.share"
    ]
  }
}
```

### Identity Fields

- **deviceId** (string, required): Unique device identifier
  - Format: UUID v4 with underscores instead of hyphens
  - Example: `a1b2c3d4_e5f6_7890_abcd_ef1234567890`
  - Must remain consistent across sessions

- **deviceName** (string, required): Human-readable device name
  - Length: 1-32 characters recommended
  - Example: "John's Laptop", "My Phone"

- **protocolVersion** (number, required): Protocol version (currently 7)

- **deviceType** (string, required): Device category
  - Valid values: `desktop`, `laptop`, `phone`, `tablet`, `tv`

- **tcpPort** (number, required): TCP port for connections
  - Range: 1716-1764 (fallback range)
  - Default: 1716

- **incomingCapabilities** (array, required): Packet types this device can receive
  - List of plugin packet types
  - Empty array is valid

- **outgoingCapabilities** (array, required): Packet types this device can send
  - List of plugin packet types
  - Empty array is valid

### Field Ordering

The official KDE Connect implementation uses this field order (should be preserved for compatibility):
1. deviceId
2. deviceName
3. protocolVersion
4. deviceType
5. tcpPort
6. incomingCapabilities
7. outgoingCapabilities

## Discovery Protocol

### Phase 1: Broadcasting

1. Device binds to UDP port 1716 (or fallback port)
2. Sets socket to broadcast mode
3. Sends identity packet to broadcast address `255.255.255.255:1716`
4. Repeats broadcast at regular intervals (default: every 5 seconds)

### Phase 2: Listening

1. Device listens on UDP port 1716
2. Receives identity packets from other devices
3. Parses and validates packet structure
4. Filters out own broadcasts (by device ID)
5. Emits discovery events for valid devices

### Phase 3: Device Tracking

1. Maintains map of discovered devices
2. Records last-seen timestamp for each device
3. Removes devices that haven't been seen for timeout period (default: 30 seconds)
4. Emits device-lost events for timed-out devices

### Discovery Packet Flow

```
Device A                          Network                          Device B
   |                                 |                                 |
   |--- Identity Broadcast --------->|                                 |
   |    (255.255.255.255:1716)       |                                 |
   |                                 |--- Identity Broadcast --------->|
   |                                 |                                 |
   |                                 |<-- Identity Broadcast ----------|
   |<-- Identity Received -----------|                                 |
   |                                 |                                 |
   |--- TCP Connection Request ----->|--- TCP Connection Request ----->|
   |    (to device B's tcpPort)      |                                 |
   |                                 |                                 |
```

## Pairing Protocol

### Overview

Devices must pair before exchanging data beyond discovery packets. Pairing establishes trust via certificate exchange.

### Pairing Steps

1. **Pairing Request**
   - Packet type: `kdeconnect.pair`
   - Body: `{ "pair": true }`

2. **User Approval**
   - Both devices prompt user for approval
   - Timeout: Typically 30 seconds

3. **Certificate Exchange**
   - Devices exchange self-signed certificates
   - Fingerprints calculated via SHA-256
   - Certificates stored in trust database

4. **Pairing Confirmation**
   - Packet type: `kdeconnect.pair`
   - Body: `{ "pair": true }`

5. **TLS Connection Established**
   - All future communication over TLS
   - Certificate pinning enforced

### Pairing Rejection

- Packet type: `kdeconnect.pair`
- Body: `{ "pair": false }`

### Unpairing

- Packet type: `kdeconnect.pair`
- Body: `{ "pair": false }`
- Removes device from trust database

## Plugin Packets

### Ping Plugin

**Purpose:** Connectivity testing and latency measurement

**Incoming Packet:**
```json
{
  "id": 1234567890123,
  "type": "kdeconnect.ping",
  "body": {
    "message": "Optional custom message"
  }
}
```

**Outgoing Packet:** Same format

### Battery Plugin

**Purpose:** Sync battery status between devices

**Battery Status Packet:**
```json
{
  "id": 1234567890123,
  "type": "kdeconnect.battery",
  "body": {
    "isCharging": true,
    "currentCharge": 85,
    "thresholdEvent": 0
  }
}
```

**Battery Request Packet:**
```json
{
  "id": 1234567890123,
  "type": "kdeconnect.battery.request",
  "body": {}
}
```

**Battery Fields:**
- **isCharging** (boolean): Whether device is charging
- **currentCharge** (number): Battery percentage (0-100)
- **thresholdEvent** (number): Battery event type
  - `0`: Normal update
  - `1`: Battery low warning

### Share Plugin

**Purpose:** File and content sharing

**Share Packet:**
```json
{
  "id": 1234567890123,
  "type": "kdeconnect.share",
  "body": {
    "filename": "document.pdf",
    "text": "Optional text content",
    "url": "https://example.com"
  },
  "payloadSize": 1048576,
  "payloadTransferInfo": {
    "port": 1739
  }
}
```

**Share Request Packet:**
```json
{
  "id": 1234567890123,
  "type": "kdeconnect.share.request",
  "body": {
    "url": "https://example.com"
  }
}
```

### Notification Plugin

**Purpose:** Cross-device notification sync

**Notification Packet:**
```json
{
  "id": 1234567890123,
  "type": "kdeconnect.notification",
  "body": {
    "id": "notification-uuid",
    "appName": "Message App",
    "ticker": "New message from John",
    "isClearable": true,
    "isCancel": false,
    "requestReplyId": "reply-uuid",
    "silent": false,
    "actions": [
      "Reply",
      "Dismiss"
    ]
  }
}
```

**Notification Request:**
```json
{
  "id": 1234567890123,
  "type": "kdeconnect.notification.request",
  "body": {}
}
```

**Notification Reply:**
```json
{
  "id": 1234567890123,
  "type": "kdeconnect.notification.reply",
  "body": {
    "requestReplyId": "reply-uuid",
    "message": "Reply message text"
  }
}
```

**Notification Action:**
```json
{
  "id": 1234567890123,
  "type": "kdeconnect.notification.action",
  "body": {
    "key": "notification-uuid",
    "action": "Reply"
  }
}
```

### MPRIS Plugin (Media Control)

**Purpose:** Remote media player control

**MPRIS Status:**
```json
{
  "id": 1234567890123,
  "type": "kdeconnect.mpris",
  "body": {
    "player": "spotify",
    "isPlaying": true,
    "pos": 45000,
    "length": 180000,
    "title": "Song Title",
    "artist": "Artist Name",
    "album": "Album Name",
    "canPause": true,
    "canPlay": true,
    "canGoNext": true,
    "canGoPrevious": true,
    "canSeek": true
  }
}
```

**MPRIS Command:**
```json
{
  "id": 1234567890123,
  "type": "kdeconnect.mpris.request",
  "body": {
    "player": "spotify",
    "action": "PlayPause",
    "Seek": 60000
  }
}
```

**Actions:** `Play`, `Pause`, `PlayPause`, `Next`, `Previous`, `Stop`, `Seek`

## Payload Transfer

### Overview

Large data (files, streams) use separate TCP connections negotiated via packets.

### Transfer Negotiation

1. Sender announces payload size and opens transfer port
2. Receiver connects to transfer port
3. Data streams until complete
4. Connection closes

### Transfer Packet

```json
{
  "id": 1234567890123,
  "type": "kdeconnect.share",
  "body": {
    "filename": "largefile.zip"
  },
  "payloadSize": 104857600,
  "payloadTransferInfo": {
    "port": 1739
  }
}
```

### Transfer Protocol

1. Sender binds to ephemeral TCP port (1739-1764 range)
2. Sender includes port in `payloadTransferInfo`
3. Receiver connects to specified port
4. Sender streams data
5. Connection closes after `payloadSize` bytes

### Indefinite Streams

For streams of unknown length:
- Set `payloadSize` to `-1`
- Stream until sender closes connection
- Used for: video streams, live data feeds

## Protocol Extensions

### Custom Plugin Development

To add custom functionality:

1. Choose unique packet type: `kdeconnect.myplugin[.action]`
2. Define packet body structure
3. Implement plugin in Rust core
4. Expose via FFI if needed
5. Implement platform-specific UI

### Capability Registration

Plugins must register capabilities in identity packet:

```rust
fn incoming_capabilities(&self) -> Vec<String> {
    vec!["kdeconnect.myplugin".to_string()]
}

fn outgoing_capabilities(&self) -> Vec<String> {
    vec!["kdeconnect.myplugin.response".to_string()]
}
```

## Compatibility Notes

### Protocol Version Negotiation

- Devices compare `protocolVersion` during discovery
- Incompatible versions refuse to pair
- Version 7 devices work with version 7 only
- Backward compatibility not guaranteed

### Implementation Variations

Different KDE Connect implementations may vary in:
- Packet field ordering (cosmetic only)
- Optional field handling
- Timeout values
- Port ranges

### Best Practices

1. **Always terminate packets with `\n`**
2. **Accept both string and number for `id` field**
3. **Preserve field ordering in identity packets**
4. **Validate all incoming packet fields**
5. **Handle missing optional fields gracefully**
6. **Filter self-broadcasts in discovery**
7. **Implement exponential backoff for retries**

## Testing Interoperability

### Recommended Test Cases

1. Discovery with official KDE Connect client
2. Discovery with GSConnect (GNOME)
3. Pairing workflow completion
4. Plugin packet exchange
5. File transfer functionality
6. Handling malformed packets
7. Timeout and reconnection
8. Multiple simultaneous connections

### Known Compatible Implementations

- KDE Connect (Linux, Windows, macOS)
- GSConnect (GNOME Shell extension)
- KDE Connect Android
- KDE Connect iOS
- Valent (GTK4 implementation)

## References

- Official KDE Connect: https://invent.kde.org/network/kdeconnect-kde
- Protocol Documentation: https://community.kde.org/KDEConnect
- Valent Protocol Reference: https://valent.andyholmes.ca/documentation/protocol.html
- Network Packet Details: https://github.com/KDE/kdeconnect-kde/tree/master/core/networkpacket.h

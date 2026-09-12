# Stationeers Network Protocol Notes

Technical details of the Stationeers dedicated server network protocol, reverse-engineered by decompiling `Assembly-CSharp.dll` from the game's managed DLLs using [ILSpy](https://github.com/icsharpcode/ILSpy), and verified/updated against live traffic via packet capture (Wireshark/tcpdump) of both a real game client and this tool.

These notes may be useful for anyone building Stationeers networking tools (RCON alternatives, server monitors, bots, etc.).

> **A note on message IDs:** the numeric values below were confirmed correct as of server version **0.2.6428.27798**. They were originally documented as `0x70`/`0x71` against an earlier build (`0.2.6136.26812`) and had drifted by the time of this update. These IDs appear to be assigned by registration order in the game's internal `MessageFactory`, so **a future game update can silently shift them again**. If this tool stops working after a Stationeers update, capturing a real client's traffic and comparing message type bytes (see "Debugging Approach" below) is the fastest way to find the new values.

## Transport Layer: RakNet

Stationeers uses RakNet over UDP with protocol version 6.

### Handshake Sequence

1. **Client → Server:** `OpenConnectionRequest1` (0x05) — includes RakNet magic bytes and MTU padding
2. **Server → Client:** `OpenConnectionReply1` (0x06) — returns negotiated MTU
3. **Client → Server:** `OpenConnectionRequest2` (0x07) — includes client GUID
4. **Server → Client:** `OpenConnectionReply2` (0x08) — connection established
5. **Client → Server:** `ConnectionRequest` (0x09) — in a reliable frame
6. **Server → Client:** `ConnectionRequestAccepted` (0x10) — in a reliable frame
7. **Client → Server:** `NewIncomingConnection` (0x13) — in a reliable frame

After step 7, the RakNet connection is established and game-level messages begin.

### RakNet Magic Bytes

```
00 FF FF 00 FE FE FE FE FD FD FD FD 12 34 56 78
```

### Reliable Frame Format (0x84)

```
[0x84]                          -- frame type
[sequence: 3 bytes LE]          -- frame sequence number
[reliability: 1 byte]           -- top 3 bits = reliability type, bit 4 = "has split" flag
                                    0x60 = reliable ordered (reliability type 3)
                                    0x40 = reliable (reliability type 2)
                                    0x00 = unreliable (reliability type 0)
[bit_length: 2 bytes BE]        -- payload length in bits
[reliable_msg_num: 3 bytes LE]  -- present if reliability type >= 2
[ordered_msg_num: 3 bytes LE]   -- present if reliability type >= 3
[ordering_channel: 1 byte]      -- present if reliability type >= 3 (RakNet-level channel,
                                    distinct from the application-layer channel byte below)
[split packet header: 12 bytes] -- present only if "has split" bit is set
[payload: N bytes]              -- the actual message data
```

Note: this "ordering channel" is a RakNet transport-layer concept (used for message ordering/multiplexing) and is **not the same thing** as the application-layer `channel` byte (`0x86`) that appears as the first byte of the payload itself. Don't confuse the two when reading captures.

### ACK Format (0xC0)

```
[0xC0]                          -- ACK type
[count: 2 bytes BE]             -- number of ranges (1)
[single_range: 1 byte]          -- 1 = single sequence number
[sequence: 3 bytes LE]          -- sequence number being ACKed
```

## Application Layer: Stationeers Messages

### Message Structure

All game messages are prefixed with a channel byte and message type byte:

```
[channel: 1 byte] [message_type: 1 byte] [payload...]
```

### Network Channels

| Channel          | Value        | Description                               |
| ---------------- | ------------ | ------------------------------------------ |
| `GeneralTraffic` | `0x86` (134) | Used for all game messages including auth |

### Message Types (MessageFactory Index)

Confirmed against server version 0.2.6428.27798:

| Type                  | Value        | Direction       | Description                    |
| --------------------- | ------------ | --------------- | ------------------------------- |
| `VerifyPlayer`        | `0x73` (115) | Client → Server | Auth response with credentials |
| `VerifyPlayerRequest` | `0x74` (116) | Server → Client | Auth challenge                 |

Other message types observed in a live capture but **not yet documented** (included here in case they're useful to future contributors — meanings are inferred from context, not confirmed):

| Type   | Value        | Direction       | Guessed purpose                                              |
| ------ | ------------ | ---------------- | -------------------------------------------------------------- |
| `0x8f` | 143          | Server → Client | Sent right after auth; payload includes an ASCII version-like string |
| `0x93` | 147          | Server → Client | Sent right after `0x8f`; includes the client's connection ID  |
| `0x70` | 112          | Client → Server | Recurring — likely a generic RPC/state-request channel, unrelated to the old `VerifyPlayer` meaning this ID used to have |
| `0x03` | 3            | Client → Server | By far the most frequent message in a live session — likely player transform/input sync sent every tick |

### Connection Methods

| Method              | Value | Description                            |
| -------------------- | ----- | ---------------------------------------- |
| `RocketNet`         | `0`   | Direct UDP (used by dedicated servers) |
| `FacepunchSteamP2P` | `1`   | Steam P2P networking                   |
| `None`              | `2`   | Not connected                          |

### String Encoding

Stationeers uses a custom binary format for strings (via `RocketBinaryWriter`), **not** the .NET 7-bit encoded integer format:

```
[length: int32 LE]  -- number of UTF-8 bytes (-1 for null)
[data: N bytes]     -- UTF-8 encoded string
```

## Authentication Flow

### VerifyPlayerRequest (Server → Client)

Sent immediately after the RakNet handshake completes:

```
[channel: 0x86]
[msg_type: 0x74]
[OwnerConnectionId: int64 LE]     -- server's host ID (-1 for dedicated)
[ClientConnectionId: int64 LE]    -- RakNet GUID assigned to this client
[PasswordRequired: bool (1 byte)]
[ConnectionMethod: byte]
[unknown: 5 bytes]                -- see "Unknown Trailing Fields" below
```

Total observed length: **25 bytes** (not 20 — see below).

### VerifyPlayer (Client → Server)

Client responds with credentials:

```
[channel: 0x86]
[msg_type: 0x73]
[OwnerConnectionId: int64 LE]     -- MUST be ClientConnectionId from request
[ClientId: uint64 LE]             -- Steam ID (not validated by server)
[Name: string]                    -- Player display name
[Password: string]                -- Server password
[Version: string]                 -- Game version (e.g. "0.2.6428.27798")
[ConnectionMethod: byte]          -- 0 for RocketNet
[unknown: 5 bytes]                -- see "Unknown Trailing Fields" below — REQUIRED, see warning
```

**Important:** omitting the trailing 5 bytes does not produce an explicit rejection message in the server log. The connection appears to proceed (`Process verify player <id>` is logged), but the client is never promoted to a fully joined state — no `Client: <name> Connected` line ever appears, and the connection silently sits idle until it's dropped or times out. If your client implementation is stuck at that exact point, check this field first.

### Unknown Trailing Fields

Both `VerifyPlayerRequest` and `VerifyPlayer` carry 5 extra bytes at the end that aren't accounted for by the structure above. In every capture examined so far, this field has the same constant value in the `VerifyPlayer` message:

```
02 00 00 00 00
```

**What this actually is has not been confirmed.** The leading working theory is that it relates to the `Invalid booster networking version` rejection message the server logs for malformed/incompatible clients — "booster" and "networking version" both point at some kind of transport/library compatibility marker, and this field's presence would fit that role. If you can confirm the real meaning (e.g. by finding the relevant code path in a decompile), please update this doc.

### Server Validation (VerifyConnection)

The server checks the following, in order:

1. **Blacklist** — is the ClientId banned?
2. **Password** — does it match the server password? (skipped if server has no password)
3. **Version** — does it match the server's game version?

The server does **not** validate Steam authentication tickets. Any ClientId is accepted as long as it passes the above checks.

### OwnerConnectionId: The Critical Detail

The `OwnerConnectionId` field in `VerifyPlayer` is stored as the client's `connectionId` in the server's client list. When a player disconnects, the server calls `Client.Find(connectionId)` using the RakNet GUID to locate and remove the client object.

If `OwnerConnectionId` doesn't match the actual RakNet GUID (which the server sends as `ClientConnectionId` in the challenge), `Client.Find()` fails, the client is never properly removed, and features like `AutoPauseServer` won't trigger.

## The LibConstruct Handshake

**This step is not optional.** Without it, authentication appears to succeed (the server logs `Process verify player <id>`) but the client is never marked as fully connected, and no join data is ever sent.

Shortly after the server sends `VerifyPlayerRequest` (and around the same time as, or shortly after, the client sends `VerifyPlayer`), the server sends a **raw RakNet system message** — *not* wrapped in the `0x86` application channel — with message ID `0xA9` (169):

```
[msg_id: 0xA9]
[payload: ~57 bytes, includes the ASCII strings "LibConstruct" and "0.3.0"]
```

The client's only obligation observed so far is to **echo this message back to the server byte-for-byte, unmodified**, wrapped in its own reliable frame. In a real client capture, the server's `0xA9` message and the client's reply were bitwise identical.

This looks like a networking-library or serializer fingerprint check, separate from and in addition to the game-version string already sent in `VerifyPlayer`. The exact structure of the payload (beyond "contains those two ASCII strings") has not been reverse-engineered field-by-field — treating it as an opaque blob to echo back has been sufficient to get a client fully connected.

## Join Data Flow

After successful authentication **and** the LibConstruct echo:

1. Server adds client to `ProcessJoinQueue`
2. Server **pauses the game** to serialize world state
3. Server sends serialized world data as join data, split across many MTU-sized fragments (observed: ~33KB compressed for a small/fresh world; scales with world size)
4. Client must ACK all RakNet frames during transfer
5. Server marks client as `Connected` (visible in the log as `Client: <name> (<id>). Connected. X / X`) when all data is sent
6. Server **unpauses the game**

The client must stay connected and ACK frames throughout this process, otherwise the server logs errors about failed join data delivery. In testing, the full join sequence (auth → LibConstruct echo → world serialization → transfer → `Connected`) completed in well under a second on localhost; it is not a slow process, so if a client implementation appears to "hang" waiting for `Connected`, the cause is more likely a missing protocol step than a timing issue.

## Debugging Approach

If this protocol drifts again on a future game update, the fastest way to re-diagnose it:

1. Capture a working real-client session: `sudo tcpdump -i any -w capture.pcap udp port <gameport>`, connect with the actual Stationeers client, walk around briefly, then disconnect cleanly.
2. Parse the capture's RakNet frames (see the frame format above) and look specifically for messages on application channel `0x86` — these carry the message type byte that tells you what changed.
3. Compare against a capture of this tool's own (failing) traffic to see exactly where the two diverge.
4. Cross-reference against the server's log output — lines like `Process verify player`, `Client: <name> Connected`, and any `Rejecting client...` messages are strong signposts for which stage is failing.

This approach — diffing a known-good real client capture against the tool's own traffic — is how every fix in this revision was found, and was considerably faster than trying to reason about the protocol from source/decompile alone.

#!/usr/bin/env python3
"""
Connect to Stationeers server as a fake client, then disconnect,
to trigger AutoPauseServer (pauses game when no clients connected).

No Steam login required - protocol reverse-engineered from game DLLs.

Usage: fake-connect.py [password] [version]
  password: Server password (default: from SERVER_PASSWORD env or empty)
  version:  Game version string (default: auto-detected from server log)
"""
import socket
import struct
import time
import random
import sys
import os

HOST = "127.0.0.1"
PORT = int(os.environ.get("GAME_PORT", "27016"))

# RakNet constants
MAGIC = bytes([0x00, 0xFF, 0xFF, 0x00, 0xFE, 0xFE, 0xFE, 0xFE,
               0xFD, 0xFD, 0xFD, 0xFD, 0x12, 0x34, 0x56, 0x78])
RAKNET_PROTOCOL_VERSION = 6

# Stationeers message constants (from decompiled MessageFactory)
CHANNEL_GENERAL_TRAFFIC = 0x86  # 134
MSG_VERIFY_PLAYER = 0x73         # 112 - client sends auth
MSG_VERIFY_PLAYER_REQUEST = 0x74 # 113 - server sends challenge
MSG_LIBCONSTRUCT_ID = 0xA9

# ConnectionMethod enum (from decompiled ConnectionMethod.cs)
CONNECTION_METHOD_ROCKETNET = 0

FAKE_STEAM_ID = 76561197967126507
FAKE_NAME = "PauseBot"


def encode_address(ip, port):
    parts = ip.split(".")
    return bytes([4] + [0xFF ^ int(p) for p in parts]) + struct.pack(">H", port)


def make_frame(seq, data):
    frame = struct.pack("B", 0x84) + struct.pack("<I", seq)[:3]
    frame += struct.pack("B", 0x60)
    frame += struct.pack(">H", len(data) * 8)
    frame += struct.pack("<I", seq)[:3]
    frame += struct.pack("<I", seq)[:3]
    frame += struct.pack("B", 0)
    frame += data
    return frame


def send_ack(sock, seq_num):
    ack = struct.pack("B", 0xC0)
    ack += struct.pack(">H", 1)
    ack += struct.pack("B", 1)
    ack += struct.pack("<I", seq_num)[:3]
    sock.sendto(ack, (HOST, PORT))

def extract_frame_data(frame):
    if not frame or frame[0] != 0x84:
        return frame
    offset = 4
    rb = frame[offset]
    rt = (rb >> 5) & 0x07
    hs = (rb >> 4) & 0x01
    offset += 1
    bl = struct.unpack(">H", frame[offset:offset + 2])[0]
    byte_len = (bl + 7) // 8
    offset += 2
    if rt >= 2:
        offset += 3
    if rt >= 3:
        offset += 4
    if hs:
        offset += 12
    return frame[offset:offset + byte_len]


def write_string(s):
    """Stationeers string format: [4-byte LE int32 length] [UTF-8 bytes]"""
    if s is None:
        return struct.pack("<i", -1)
    encoded = s.encode("utf-8")
    return struct.pack("<i", len(encoded)) + encoded


def detect_version():
    """Auto-detect game version from server log."""
    log_path = os.environ.get("LOG_FILE", "/home/steam/stationeers/logs/server.log")
    try:
        with open(log_path, "r") as f:
            for line in f:
                if "Version : " in line:
                    return line.split("Version : ")[1].strip()
    except (IOError, IndexError):
        pass
    return None


def raknet_connect(sock):
    guid = random.getrandbits(63)
    seq = 0
    sock.settimeout(5.0)

    req1 = struct.pack("B", 0x05) + MAGIC + struct.pack("B", RAKNET_PROTOCOL_VERSION)
    req1 += b'\x00' * (1400 - len(req1))
    sock.sendto(req1, (HOST, PORT))
    resp = sock.recvfrom(4096)[0]
    if resp[0] != 0x06:
        raise RuntimeError(f"Expected Reply1 (0x06), got 0x{resp[0]:02x}")
    mtu = struct.unpack(">H", resp[26:28])[0]

    req2 = struct.pack("B", 0x07) + MAGIC + encode_address(HOST, PORT)
    req2 += struct.pack(">H", mtu) + struct.pack(">q", guid)
    sock.sendto(req2, (HOST, PORT))
    resp = sock.recvfrom(4096)[0]
    if resp[0] != 0x08:
        raise RuntimeError(f"Expected Reply2 (0x08), got 0x{resp[0]:02x}")

    conn_req = struct.pack("B", 0x09) + struct.pack(">q", guid)
    conn_req += struct.pack(">Q", int(time.time() * 1000)) + struct.pack("B", 0)
    sock.sendto(make_frame(seq, conn_req), (HOST, PORT))
    seq += 1

    for _ in range(10):
        resp = sock.recvfrom(4096)[0]
        if resp[0] == 0x84:
            s = struct.unpack("<I", resp[1:4] + b'\x00')[0]
            send_ack(sock, s)
            data = extract_frame_data(resp)
            if data and data[0] == 0x10:
                break
        elif resp[0] == 0xC0:
            pass

    nic = struct.pack("B", 0x13) + encode_address(HOST, PORT)
    for _ in range(10):
        nic += encode_address("127.0.0.1", PORT)
    nic += struct.pack(">Q", int(time.time() * 1000)) * 2
    sock.sendto(make_frame(seq, nic), (HOST, PORT))
    seq += 1

    return seq


def build_verify_player(owner_conn_id, client_id, name, password, version, conn_method):
    msg = bytes([CHANNEL_GENERAL_TRAFFIC, MSG_VERIFY_PLAYER])
    msg += struct.pack("<q", owner_conn_id)
    msg += struct.pack("<Q", client_id)
    msg += write_string(name)
    msg += write_string(password)
    msg += write_string(version)
    msg += struct.pack("B", conn_method)
    msg += b'\x02\x00\x00\x00\x00'  # booster networking version field — required, matches server's own tail
    return msg


def stay_connected(sock, seq, duration):
    sock.settimeout(0.5)
    start = time.time()
    while time.time() - start < duration:
        try:
            resp = sock.recvfrom(65535)[0]
            if resp[0] == 0x84:
                s = struct.unpack("<I", resp[1:4] + b'\x00')[0]
                send_ack(sock, s)
                data = extract_frame_data(resp)
                if data and data[0] == MSG_LIBCONSTRUCT_ID:
                    # Echo the fingerprint verbatim — required to be treated as fully connected
                    sock.sendto(make_frame(seq, data), (HOST, PORT))
                    seq += 1
        except socket.timeout:
            ping = struct.pack("B", 0x00) + struct.pack(">Q", int(time.time() * 1000))
            sock.sendto(make_frame(seq, ping), (HOST, PORT))
            seq += 1
    return seq


def main():
    password = os.environ.get("SERVER_PASSWORD", "")
    version = None

    if len(sys.argv) > 1:
        password = sys.argv[1]
    if len(sys.argv) > 2:
        version = sys.argv[2]

    if not version:
        version = detect_version()
    if not version:
        print("ERROR: Could not detect game version", file=sys.stderr)
        sys.exit(1)

    print(f"Triggering AutoPauseServer on {HOST}:{PORT} (version {version})")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)

    try:
        seq = raknet_connect(sock)

        # Wait for VerifyPlayerRequest
        sock.settimeout(5.0)
        client_conn_id = 0
        got_request = False
        for _ in range(15):
            try:
                resp = sock.recvfrom(4096)[0]
                if resp[0] == 0x84:
                    s = struct.unpack("<I", resp[1:4] + b'\x00')[0]
                    send_ack(sock, s)
                    data = extract_frame_data(resp)
                    if data and len(data) >= 20 and data[0] == CHANNEL_GENERAL_TRAFFIC and data[1] == MSG_VERIFY_PLAYER_REQUEST:
                        client_conn_id = struct.unpack("<q", data[10:18])[0]
                        got_request = True
                        break
                elif resp[0] == 0xC0:
                    pass
            except socket.timeout:
                ping = struct.pack("B", 0x00) + struct.pack(">Q", int(time.time() * 1000))
                sock.sendto(make_frame(seq, ping), (HOST, PORT))
                seq += 1

        if not got_request:
            print("ERROR: No VerifyPlayerRequest received", file=sys.stderr)
            sys.exit(1)

        # Send VerifyPlayer with correct OwnerConnectionId
        verify_msg = build_verify_player(
            owner_conn_id=client_conn_id,
            client_id=FAKE_STEAM_ID,
            name=FAKE_NAME,
            password=password,
            version=version,
            conn_method=CONNECTION_METHOD_ROCKETNET,
        )
        sock.sendto(make_frame(seq, verify_msg), (HOST, PORT))
        seq += 1

        # Stay connected to receive join data
        seq = stay_connected(sock, seq, 10)

        # Disconnect
        disc = struct.pack("B", 0x15)
        sock.sendto(make_frame(seq, disc), (HOST, PORT))
        sock.close()

        print("Disconnected. AutoPauseServer will trigger in ~10 seconds.")

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sock.close()
        sys.exit(1)


if __name__ == "__main__":
    main()

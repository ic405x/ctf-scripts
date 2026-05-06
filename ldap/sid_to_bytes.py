#!/usr/bin/env python3
import struct
import sys

def sid_to_ldap_hex(sid_str):
    parts = sid_str.split('-')
    rev = int(parts[1])
    auth = int(parts[2])
    subs = [int(x) for x in parts[3:]]
    b = struct.pack('<BB', rev, len(subs))
    b += struct.pack('>Q', auth)[2:]
    b += b''.join(struct.pack('<I', s) for s in subs)
    return ''.join(f'\\{byte:02x}' for byte in b)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <SID>")
        sys.exit(1)

    hex_sid = sid_to_ldap_hex(sys.argv[1])

    # Can query next with ldapsearch -x -H ldap://<DC_IP> -D <USER> -w <PASS> -b 'DC=<DC>,DC=<DC>' '(&(objectClass=computer)(ms-DS-CreatorSID=<SID_BYTES>))' name
    print(hex_sid)

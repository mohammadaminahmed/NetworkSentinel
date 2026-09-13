import struct

def parse(data: bytes) -> dict:
    """
    Parse ARP packet from raw bytes.
    Args:
        data: Raw packet bytes
    Returns:
        dict containing ARP fields or empty dict if invalid.
    """
    if len(data) < 42:
        return {}
    
    eth_header = data[:14]
    eth_type = struct.unpack("!H", eth_header[12:14])[0]
    
    if eth_type != 0x0806: # Not ARP
        return {}
        
    arp_header = data[14:42]
    arp_unpacked = struct.unpack("!HHBBH6s4s6s4s", arp_header)
    
    return {
        "hardware_type": arp_unpacked[0],
        "protocol_type": arp_unpacked[1],
        "op": "request" if arp_unpacked[4] == 1 else "reply",
        "sender_mac": ':'.join(f'{b:02x}' for b in arp_unpacked[5]),
        "sender_ip": '.'.join(str(b) for b in arp_unpacked[6]),
        "target_mac": ':'.join(f'{b:02x}' for b in arp_unpacked[7]),
        "target_ip": '.'.join(str(b) for b in arp_unpacked[8])
    }

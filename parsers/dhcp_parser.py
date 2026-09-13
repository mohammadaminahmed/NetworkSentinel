import struct

def parse(data: bytes) -> dict:
    """
    Parse a DHCP (BOOTP) payload.
    Args:
        data: Raw DHCP bytes (starting at BOOTP header)
    Returns:
        dict containing DHCP fields or empty dict if invalid.
    """
    if len(data) < 240:
        return {}
        
    # Attempt to strip Ethernet/IP/UDP headers if present (Live Capture)
    offset = 0
    if len(data) > 34:
        if (data[0] >> 4) == 4: # Raw IPv4
            ip_hlen = (data[0] & 0x0F) * 4
            protocol = data[9]
            if protocol == 17: # UDP
                offset = ip_hlen + 8
        elif (data[14] >> 4) == 4: # Ethernet -> IPv4
            ip_hlen = (data[14] & 0x0F) * 4
            protocol = data[14 + 9]
            if protocol == 17: # UDP
                offset = 14 + ip_hlen + 8
                
    dhcp_payload = data[offset:] if offset > 0 else data
    if len(dhcp_payload) < 240: # Minimum BOOTP + Magic Cookie length
        return {}
        
    try:
        header = struct.unpack("!BBBBIHH4s4s4s4s16s64s128s4s", dhcp_payload[:240])
        op = header[0]
        xid = header[4]
        ciaddr = ".".join(str(b) for b in header[7])
        yiaddr = ".".join(str(b) for b in header[8])
        siaddr = ".".join(str(b) for b in header[9])
        chaddr = ':'.join(f'{b:02x}' for b in header[11][:header[2]]) if header[2] > 0 else ""
        magic_cookie = header[14]
        
        if magic_cookie != b'\x63\x82\x53\x63':
            return {} # Not a DHCP packet
            
        options_data = data[240:]
        options = {}
        
        i = 0
        while i < len(options_data):
            opt_type = options_data[i]
            if opt_type == 255: # End option
                break
            if opt_type == 0: # Pad option
                i += 1
                continue
                
            if i + 1 >= len(options_data):
                break
            opt_len = options_data[i+1]
            if i + 2 + opt_len > len(options_data):
                break
                
            opt_val = options_data[i+2:i+2+opt_len]
            
            if opt_type == 53 and opt_len == 1:
                options['message_type'] = opt_val[0]
            elif opt_type == 54 and opt_len == 4:
                options['server_id'] = ".".join(str(b) for b in opt_val)
                
            i += 2 + opt_len

        return {
            "op": "request" if op == 1 else "reply",
            "xid": xid,
            "client_ip": ciaddr,
            "your_ip": yiaddr,
            "server_ip": siaddr,
            "client_mac": chaddr,
            "options": options
        }
    except Exception:
        return {}

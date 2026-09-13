import struct

def parse(data: bytes) -> dict:
    """
    Parse a DNS payload.
    Args:
        data: Raw DNS bytes (starting at DNS header)
    Returns:
        dict containing DNS fields or empty dict if invalid.
    """
    if len(data) < 12:
        return {}
        
    # Attempt to strip Ethernet/IP/UDP headers if present (Live Capture)
    offset = 0
    src_ip = None
    if len(data) > 34:
        import socket
        if (data[0] >> 4) == 4: # Raw IPv4
            src_ip = socket.inet_ntoa(data[12:16])
            ip_hlen = (data[0] & 0x0F) * 4
            protocol = data[9]
            if protocol == 17: # UDP
                offset = ip_hlen + 8
        elif (data[14] >> 4) == 4: # Ethernet -> IPv4
            src_ip = socket.inet_ntoa(data[26:30])
            ip_hlen = (data[14] & 0x0F) * 4
            protocol = data[14 + 9]
            if protocol == 17: # UDP
                offset = 14 + ip_hlen + 8
                
    dns_payload = data[offset:] if offset > 0 else data
    if len(dns_payload) < 12:
        return {}
    
    try:
        header = struct.unpack("!HHHHHH", dns_payload[:12])
        transaction_id = header[0]
        flags = header[1]
        qdcount = header[2]
        
        is_response = (flags & 0x8000) != 0
        
        offset = 12
        questions = []
        
        for _ in range(qdcount):
            name_parts = []
            while True:
                if offset >= len(data):
                    break
                length = data[offset]
                if length == 0:
                    offset += 1
                    break
                if (length & 0xC0) == 0xC0: # Pointer (compression)
                    offset += 2
                    break
                offset += 1
                name_parts.append(data[offset:offset+length].decode('utf-8', errors='ignore'))
                offset += length
            
            qname = ".".join(name_parts)
            if offset + 4 <= len(data):
                qtype, qclass = struct.unpack("!HH", data[offset:offset+4])
                offset += 4
                questions.append({"name": qname, "type": qtype, "class": qclass})
                
        return {
            "transaction_id": transaction_id,
            "flags": flags,
            "is_response": is_response,
            "questions": questions,
            "answers": [],
            "src_ip": src_ip
        }
    except Exception:
        return {}

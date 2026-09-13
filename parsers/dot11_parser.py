import struct

def parse(data: bytes) -> dict:
    """
    Parse an 802.11 MAC header.
    Args:
        data: Raw 802.11 frame bytes (assuming Radiotap header is stripped)
    Returns:
        dict containing 802.11 fields or empty dict if invalid.
    """
    if len(data) < 24:
        return {}
        
    try:
        frame_control = struct.unpack("<H", data[0:2])[0]
        
        # In frame_control (little endian):
        # b0-1: Protocol version
        # b2-3: Type
        # b4-7: Subtype
        
        version = frame_control & 0x0003
        frame_type = (frame_control >> 2) & 0x0003
        subtype = (frame_control >> 4) & 0x000F
        
        addr1 = ':'.join(f'{b:02x}' for b in data[4:10])
        addr2 = ':'.join(f'{b:02x}' for b in data[10:16])
        addr3 = ':'.join(f'{b:02x}' for b in data[16:22])
        
        # Map frame type and subtype to human readable for Management frames
        type_str = "unknown"
        if frame_type == 0:
            if subtype == 8: type_str = "Beacon"
            elif subtype == 12: type_str = "Deauth"
            else: type_str = "Management"
        elif frame_type == 1: type_str = "Control"
        elif frame_type == 2: type_str = "Data"
        
        return {
            "type": frame_type,
            "subtype": subtype,
            "type_str": type_str,
            "addr1": addr1, # Receiver
            "addr2": addr2, # Transmitter
            "addr3": addr3, # BSSID
            "bssid": addr3
        }
    except Exception:
        return {}

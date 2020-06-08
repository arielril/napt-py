def bytes_to_mac(bytesmac: bytearray) -> str:
    return ':'.join('{:02x}'.format(x) for x in bytesmac)

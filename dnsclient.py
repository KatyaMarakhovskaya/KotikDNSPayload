import binascii
import socket

#This was only to understand DNS and us a test script . 
#Nothing more.

def send_udp_message(message, address, port):
    """send_udp_message sends a message to UDP server

    message should be a hexadecimal encoded string
    """
    message = message.replace(" ", "").replace("\n", "")
    server_address = (address, port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(binascii.unhexlify(message), server_address)
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    return binascii.hexlify(data).decode("utf-8")


def format_hex(hex):
    """format_hex returns a pretty version of a hex string"""
    octets = [hex[i:i+2] for i in range(0, len(hex), 2)]
    pairs = [" ".join(octets[i:i+2]) for i in range(0, len(octets), 2)]
    return "\n".join(pairs)


message = "AA AA 01 00 00 01 00 00 00 00 00 00 " \
"07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 01 00 01"


#message = "AA AA 01 00 00 01 00 00 00 00 00 00 " \
#"0A 72 6f 6f 74 6b 69 74 64 65 76 03 63 6f 6d 00 00 01 00 01" 

# 72 6f 6f 74 6b 69 74 64 65 76

response = send_udp_message(message, "8.8.8.8", 53)
print(format_hex(response))


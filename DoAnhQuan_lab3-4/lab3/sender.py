import os
import socket
from des_socket_utils import encrypt_des_cbc, build_packet

SERVER_IP = os.getenv('SERVER_IP', '127.0.0.1')
SERVER_PORT = int(os.getenv('SERVER_PORT', '6000'))

def get_message() -> bytes:
    plain = input("Nhập bản tin: ")
    return plain.encode('utf-8')

def main() -> None:
    plain = get_message()

    key, iv, cipher_bytes = encrypt_des_cbc(plain)
    packet = build_packet(key, iv, cipher_bytes)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((SERVER_IP, SERVER_PORT))
        s.sendall(packet)

    print("[+] Đã gửi bản mã.")
    print(f"Key: {key.hex()}")
    print(f"IV: {iv.hex()}")
    print(f"Ciphertext: {cipher_bytes.hex()}")

if __name__ == '__main__':
    main()
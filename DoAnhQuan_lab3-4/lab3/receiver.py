import os
import socket
from des_socket_utils import HEADER_SIZE, parse_header, recv_exact, decrypt_des_cbc

HOST = os.getenv('RECEIVER_HOST', '0.0.0.0')
PORT = int(os.getenv('RECEIVER_PORT', '6000'))

def main() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()

        print(f"Đang lắng nghe {HOST}:{PORT}...")

        while True:  # 🔥 chạy liên tục, không bị tắt
            conn, addr = s.accept()
            with conn:
                print(f"Kết nối từ {addr}")

                try:
                    header = recv_exact(conn, HEADER_SIZE)
                    key, iv, length = parse_header(header)

                    cipher_bytes = recv_exact(conn, length)
                    plaintext = decrypt_des_cbc(key, iv, cipher_bytes)

                    message = plaintext.decode('utf-8', errors='ignore')
                    print(f"[+] Bản tin gốc: {message}")

                except Exception as e:
                    print(f"[!] Lỗi khi xử lý dữ liệu: {e}")

if __name__ == '__main__':
    main()
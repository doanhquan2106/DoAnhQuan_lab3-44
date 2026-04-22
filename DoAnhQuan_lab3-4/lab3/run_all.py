import socket
import threading
import time
from des_socket_utils import (
    HEADER_SIZE, parse_header, recv_exact,
    decrypt_des_cbc, encrypt_des_cbc, build_packet
)

HOST = '127.0.0.1'
PORT = 6000

# ================= SERVER =================
def run_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[SERVER] Đang lắng nghe {HOST}:{PORT}...")

        conn, addr = s.accept()
        with conn:
            print(f"[SERVER] Kết nối từ {addr}")

            header = recv_exact(conn, HEADER_SIZE)
            key, iv, length = parse_header(header)

            cipher_bytes = recv_exact(conn, length)
            plaintext = decrypt_des_cbc(key, iv, cipher_bytes)

            message = plaintext.decode('utf-8', errors='ignore')
            print(f"[SERVER] Bản tin gốc: {message}")


# ================= CLIENT =================
def run_client():
    time.sleep(1)  # 🔥 chờ server chạy trước

    plain = input("[CLIENT] Nhập bản tin: ").encode('utf-8')

    key, iv, cipher_bytes = encrypt_des_cbc(plain)
    packet = build_packet(key, iv, cipher_bytes)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(packet)

    print("[CLIENT] Đã gửi!")
    print(f"Key: {key.hex()}")
    print(f"IV: {iv.hex()}")
    print(f"Cipher: {cipher_bytes.hex()}")


# ================= MAIN =================
def main():
    server_thread = threading.Thread(target=run_server)
    client_thread = threading.Thread(target=run_client)

    server_thread.start()
    client_thread.start()

    server_thread.join()
    client_thread.join()


if __name__ == "__main__":
    main()
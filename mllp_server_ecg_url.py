#!/usr/bin/env python3
import argparse
import base64
import socket
import threading
from datetime import datetime

from hl7apy.core import Message
from hl7apy.parser import parse_message
from kyber_py.ml_kem import ML_KEM_512

MLLP_SB = b"\x0b"  # <VT>
MLLP_EB = b"\x1c"  # <FS>
MLLP_CR = b"\x0d"  # <CR>


def wrap_mllp(hl7_text: str) -> bytes:
    return MLLP_SB + hl7_text.encode("utf-8") + MLLP_EB + MLLP_CR


def read_mllp(sock: socket.socket) -> str:
    """Read one HL7 frame until <FS><CR>; strip MLLP envelope."""
    buf = bytearray()
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf.extend(chunk)
        if b"\x1c\x0d" in buf:
            break
    if not buf:
        return ""
    if buf.startswith(MLLP_SB) and buf.endswith(MLLP_EB + MLLP_CR):
        buf = buf[len(MLLP_SB):-len(MLLP_EB + MLLP_CR)]
    return buf.decode("utf-8", errors="ignore")


def build_ack(orig_msg, ack_code="AA", text="Message accepted"):
    ack = Message("ACK", version="2.5")
    # MSH
    ack.msh.msh_3 = "ServerApp"
    ack.msh.msh_4 = "ServerFacility"
    ack.msh.msh_5 = "ClientApp"
    ack.msh.msh_6 = "ClientFacility"
    ack.msh.msh_7 = datetime.now().strftime("%Y%m%d%H%M%S")
    ack.msh.msh_9 = "ACK"
    ack.msh.msh_10 = datetime.now().strftime("%H%M%S%f")
    ack.msh.msh_11 = "P"
    ack.msh.msh_12 = "2.5"
    # MSA
    ack.msa.msa_1 = ack_code
    ack.msa.msa_2 = (orig_msg.msh.msh_10.to_er7() if orig_msg and orig_msg.msh and orig_msg.msh.msh_10 else "UNKNOWN")
    ack.msa.msa_3 = text
    return ack


def build_rsp_k11(orig_msg, b64_public_key: str):
    """Simple flat RSP^K11: OBX is at message root (no groups)."""
    rsp = Message("RSP_K11", version="2.5")
    # MSH
    rsp.msh.msh_3 = "ServerApp"
    rsp.msh.msh_4 = "ServerFacility"
    rsp.msh.msh_5 = "ClientApp"
    rsp.msh.msh_6 = "ClientFacility"
    rsp.msh.msh_7 = datetime.now().strftime("%Y%m%d%H%M%S")
    rsp.msh.msh_9 = "RSP^K11"
    rsp.msh.msh_10 = datetime.now().strftime("%H%M%S%f")
    rsp.msh.msh_11 = "P"
    rsp.msh.msh_12 = "2.5"

    # MSA (ack of the query)
    rsp.msa.msa_1 = "AA"
    rsp.msa.msa_2 = (orig_msg.msh.msh_10.to_er7() if orig_msg and orig_msg.msh and orig_msg.msh.msh_10 else "UNKNOWN")

    # QAK
    qak = rsp.add_segment("QAK")
    qak.qak_1 = "KYBER_PK"
    qak.qak_2 = "OK"

    # QPD echo (optional)
    try:
        inbound_qpd = orig_msg.qpd
        qpd = rsp.add_segment("QPD")
        qpd.qpd_1 = inbound_qpd.qpd_1.to_er7() or "KYBER_PK"
        qpd.qpd_2 = inbound_qpd.qpd_2.to_er7() or "QUERY"
        qpd.qpd_3 = inbound_qpd.qpd_3.to_er7() or ""
    except Exception:
        pass

    # OBX with public key (base64), at root
    obx = rsp.add_segment("OBX")
    obx.obx_1 = "1"
    obx.obx_2 = "TX"
    obx.obx_3 = "KYBER_PK^Kyber Public Key"
    obx.obx_5 = b64_public_key
    obx.obx_11 = "F"

    return rsp


class MLLPServer(threading.Thread):
    def __init__(self, host, port):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.ek, self.dk = ML_KEM_512.keygen()
        print("[INFO] ML_KEM_512 keypair generated. PK bytes:", len(self.ek), "SK bytes:", len(self.dk))

    def handle_client(self, conn, addr):
        try:
            hl7_text = read_mllp(conn)
            if not hl7_text:
                conn.close()
                return
            print(f"\n[RECV from {addr}] ----------------------")
            print(hl7_text.replace("\r", "\n"))
            print("----------------------------------------")

            try:
                msg = parse_message(hl7_text, validation_level=2)
                msg_type = (msg.msh.msh_9.to_er7()).upper()
            except Exception as e:
                print("[ERROR] HL7 parse:", e)
                nack = build_ack(Message("ACK", version="2.5"), ack_code="AE", text="Parse error")
                conn.sendall(wrap_mllp(nack.to_er7()))
                return

            if msg_type.startswith("QBP^Q11"):
                b64_pk = base64.b64encode(self.ek).decode()
                rsp = build_rsp_k11(msg, b64_pk)
                print("[DEBUG] RSP^K11 sent:\n" + rsp.to_er7().replace("\r", "\n"))
                conn.sendall(wrap_mllp(rsp.to_er7()))
            elif msg_type.startswith("ORU^R01"):
                ack = build_ack(msg, "AA", "ORU received")
                conn.sendall(wrap_mllp(ack.to_er7()))
                print("[INFO] ORU^R01 ACK (AA) sent.")
            else:
                ack = build_ack(msg, "AE", f"Unsupported message type {msg_type}")
                conn.sendall(wrap_mllp(ack.to_er7()))
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen(5)
            print(f"[LISTENING] MLLP on {self.host}:{self.port}")
            while True:
                conn, addr = s.accept()
                threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()


def main():
    ap = argparse.ArgumentParser(description="HL7 MLLP Server (Kyber PK + ORU ACK)")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=2575)
    args = ap.parse_args()
    MLLPServer(args.host, args.port).run()


if __name__ == "__main__":
    main()

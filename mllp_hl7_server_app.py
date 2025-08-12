#!/usr/bin/env python3
import argparse
import base64
import os
import socket
import threading
from datetime import datetime
from json import loads, dumps

from hl7apy.core import Message
from hl7apy.parser import parse_message
from kyber_py.ml_kem import ML_KEM_512
from pyascon.ascon import ascon_decrypt  # Ascon-128

# ----------------- MLLP framing -----------------
MLLP_SB = b"\x0b"  # <VT>
MLLP_EB = b"\x1c"  # <FS>
MLLP_CR = b"\x0d"  # <CR>


def wrap_mllp(hl7_text: str) -> bytes:
    return MLLP_SB + hl7_text.encode("utf-8") + MLLP_EB + MLLP_CR


def read_mllp(sock: socket.socket) -> str:
    buf = bytearray()
    while True:
        try:
            chunk = sock.recv(4096)
        except ConnectionResetError:
            break
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


# ----------------- HL7 helpers -----------------
def build_ack(orig_msg, ack_code="AA", text="OK"):
    ack = Message("ACK", version="2.5")
    ack.msh.msh_3 = "ServerApp"
    ack.msh.msh_4 = "ServerFacility"
    ack.msh.msh_5 = "ClientApp"
    ack.msh.msh_6 = "ClientFacility"
    ack.msh.msh_7 = datetime.now().strftime("%Y%m%d%H%M%S")
    ack.msh.msh_9 = "ACK"
    ack.msh.msh_10 = datetime.now().strftime("%H%M%S%f")
    ack.msh.msh_11 = "P"
    ack.msh.msh_12 = "2.5"
    ack.msa.msa_1 = ack_code
    try:
        ack.msa.msa_2 = (orig_msg.msh.msh_10.to_er7() if orig_msg and orig_msg.msh and orig_msg.msh.msh_10 else "UNKNOWN")
    except Exception:
        ack.msa.msa_2 = "UNKNOWN"
    ack.msa.msa_3 = text
    return ack


def build_rsp_k11(orig_msg, b64_public_key: str):
    rsp = Message("RSP_K11", version="2.5")
    rsp.msh.msh_3 = "ServerApp"
    rsp.msh.msh_4 = "ServerFacility"
    rsp.msh.msh_5 = "ClientApp"
    rsp.msh.msh_6 = "ClientFacility"
    rsp.msh.msh_7 = datetime.now().strftime("%Y%m%d%H%M%S")
    rsp.msh.msh_9 = "RSP^K11"
    rsp.msh.msh_10 = datetime.now().strftime("%H%M%S%f")
    rsp.msh.msh_11 = "P"
    rsp.msh.msh_12 = "2.5"

    rsp.msa.msa_1 = "AA"
    try:
        rsp.msa.msa_2 = (orig_msg.msh.msh_10.to_er7() if orig_msg and orig_msg.msh and orig_msg.msh.msh_10 else "UNKNOWN")
    except Exception:
        rsp.msa.msa_2 = "UNKNOWN"

    qak = rsp.add_segment("QAK")
    qak.qak_1 = "KYBER_PK"
    qak.qak_2 = "OK"

    try:
        inbound_qpd = orig_msg.qpd
        qpd = rsp.add_segment("QPD")
        qpd.qpd_1 = inbound_qpd.qpd_1.to_er7() or "KYBER_PK"
        qpd.qpd_2 = inbound_qpd.qpd_2.to_er7() or "QUERY"
        qpd.qpd_3 = inbound_qpd.qpd_3.to_er7() or ""
    except Exception:
        pass

    obx = rsp.add_segment("OBX")
    obx.obx_1 = "1"
    obx.obx_2 = "TX"
    obx.obx_3 = "KYBER_PK^Kyber Public Key"
    obx.obx_5 = b64_public_key
    obx.obx_11 = "F"
    return rsp


def parse_obx_values(er7: str) -> dict:
    out = {}
    for line in er7.replace("\n", "\r").split("\r"):
        if not line or not line.startswith("OBX|"):
            continue
        fields = line.split("|")
        if len(fields) < 6:
            continue
        obx3 = fields[3]
        key = obx3.split("^", 1)[0] if obx3 else ""
        out[key] = fields[5]
    return out


# ----------------- MLLP Server -----------------
class MLLPServer(threading.Thread):
    def __init__(self, host, port, save_dir: str):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.save_dir = save_dir
        os.makedirs(self.save_dir, exist_ok=True)
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

            # Robust parse: try strict (validation_level=2), then lenient fallback
            try:
                msg = parse_message(hl7_text, validation_level=2)
            except Exception:
                try:
                    msg = parse_message(hl7_text, validation_level=1)
                except Exception as e2:
                    print("[ERROR] HL7 parse:", e2)
                    nack = build_ack(None, ack_code="AE", text="Parse error")
                    conn.sendall(wrap_mllp(nack.to_er7()))
                    return

            try:
                msg_type = (msg.msh.msh_9.to_er7()).upper()
            except Exception:
                msg_type = "UNKNOWN"

            if msg_type.startswith("QBP^Q11"):
                b64_pk = base64.b64encode(self.ek).decode()
                rsp = build_rsp_k11(msg, b64_pk)
                print("[DEBUG] RSP^K11 sent:\n" + rsp.to_er7().replace("\r", "\n"))
                conn.sendall(wrap_mllp(rsp.to_er7()))

            elif msg_type.startswith("ORU^R01"):
                obx_map = parse_obx_values(hl7_text)
                missing = [k for k in ("ECG_CIPHERTEXT_B64", "NONCE_B64", "KYBER_CT_B64") if k not in obx_map]
                if missing:
                    ack = build_ack(msg, "AE", f"Missing OBX(s): {', '.join(missing)}")
                    conn.sendall(wrap_mllp(ack.to_er7()))
                    return

                # Decode b64 payloads
                try:
                    ciphertext = base64.b64decode(obx_map["ECG_CIPHERTEXT_B64"])
                    nonce = base64.b64decode(obx_map["NONCE_B64"])
                    kyber_ct = base64.b64decode(obx_map["KYBER_CT_B64"])
                except Exception as e:
                    ack = build_ack(msg, "AE", f"Base64 decode error: {e}")
                    conn.sendall(wrap_mllp(ack.to_er7()))
                    return

                # Save encrypted file (for audit)
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                enc_filename = f"ecg_encrypted_{timestamp}.bin"
                enc_filepath = os.path.join(self.save_dir, enc_filename)
                try:
                    with open(enc_filepath, "wb") as f:
                        f.write(ciphertext)
                    print(f"[INFO] Encrypted ECG saved to {enc_filepath}")
                except Exception as e:
                    ack = build_ack(msg, "AE", f"Failed to save encrypted file: {e}")
                    conn.sendall(wrap_mllp(ack.to_er7()))
                    return

                # Kyber decapsulation
                try:
                    shared_key = ML_KEM_512.decaps(self.dk, kyber_ct)
                    ascon_key = shared_key[:16]
                except Exception as e:
                    ack = build_ack(msg, "AE", f"Kyber decapsulation failed: {e}")
                    conn.sendall(wrap_mllp(ack.to_er7()))
                    return

                # Ascon decrypt + persist plaintext
                try:
                    plaintext = ascon_decrypt(key=ascon_key, nonce=nonce, ciphertext=ciphertext, associateddata=b"")
                    decrypted_str = plaintext.decode()
                    dt_format = obx_map.get("ECG_FORMAT", "JSON").upper()

                    if dt_format == "XML":
                        filename = f"ecg_decrypted_{timestamp}.xml"
                        filepath = os.path.join(self.save_dir, filename)
                        with open(filepath, "w", encoding="utf-8") as f:
                            f.write(decrypted_str)
                        print(f"[INFO] Decrypted ECG XML saved to {filepath}")
                    else:
                        try:
                            json_data = loads(decrypted_str)
                            filename = f"ecg_decrypted_{timestamp}.json"
                            filepath = os.path.join(self.save_dir, filename)
                            with open(filepath, "w", encoding="utf-8") as f:
                                f.write(dumps(json_data, indent=2))
                            print(f"[INFO] Decrypted ECG JSON saved to {filepath}")
                        except Exception as e:
                            ack = build_ack(msg, "AE", f"Failed to parse JSON: {e}")
                            conn.sendall(wrap_mllp(ack.to_er7()))
                            return

                except Exception as e:
                    ack = build_ack(msg, "AE", f"Ascon decrypt failed: {e}")
                    conn.sendall(wrap_mllp(ack.to_er7()))
                    return

                ack = build_ack(msg, "AA", "ORU received and decrypted")
                conn.sendall(wrap_mllp(ack.to_er7()))
                print("[INFO] ORU^R01 processed successfully >>.")

            else:
                ack = build_ack(msg, "AE", f"Unsupported message type {msg_type}")
                conn.sendall(wrap_mllp(ack.to_er7()))

        except Exception as e:
            # Last-resort safety: never drop the socket without a framed response
            try:
                nack = build_ack(None, ack_code="AE", text=f"Server error: {e}")
                conn.sendall(wrap_mllp(nack.to_er7()))
            except Exception:
                pass
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
            print(f"[LISTENING] MLLP on {self.host}:{self.port}  (saving to: {self.save_dir})")
            while True:
                conn, addr = s.accept()
                threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()


def main():
    ap = argparse.ArgumentParser(description="HL7 MLLP Server (PK responder + decrypt ORU)")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=2575)
    ap.add_argument("--save-dir", default="./inbox", help="Directory to write decrypted ECG files")
    args = ap.parse_args()
    MLLPServer(args.host, args.port, args.save_dir).run()


if __name__ == "__main__":
    main()

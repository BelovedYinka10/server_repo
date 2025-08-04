import os
import json
import numpy as np
import pandas as pd
import tracemalloc  # Make sure this is imported at the top
import plotly.graph_objects as go
from flask import Flask, request, render_template, send_file, jsonify
from smaj_kyber import keygen, decapsulate, set_mode
from pyascon.ascon import ascon_decrypt
from hl7apy.parser import parse_message
from kyber_py.ml_kem import ML_KEM_512
import base64
import time
import cycles  # Your custom rdtsc module
import ctypes

app = Flask(__name__)

# === Key Paths ===
KEY_DIR = os.path.join(app.root_path, "keys")
pubkey_path = os.path.join(KEY_DIR, "server_pubkey.bin")
seckey_path = os.path.join(KEY_DIR, "server_seckey.bin")

# Load the shared library
lib = ctypes.CDLL(os.path.abspath("./libascon.dylib"))

Uint8Array = ctypes.POINTER(ctypes.c_ubyte)
ULongPtr = ctypes.POINTER(ctypes.c_ulonglong)

# Define function prototypes
lib.crypto_aead_encrypt.argtypes = [Uint8Array, ULongPtr, Uint8Array, ctypes.c_ulonglong,
                                    Uint8Array, ctypes.c_ulonglong, Uint8Array,
                                    Uint8Array, Uint8Array]
lib.crypto_aead_encrypt.restype = ctypes.c_int

lib.crypto_aead_decrypt.argtypes = [Uint8Array, ULongPtr, Uint8Array, Uint8Array,
                                    ctypes.c_ulonglong, Uint8Array, ctypes.c_ulonglong,
                                    Uint8Array, Uint8Array]
lib.crypto_aead_decrypt.restype = ctypes.c_int

# === Use a real Python string ===
message = "Hello, ECG Server 👋🏽 Secure transmission in progress."

msg_bytes = message.encode("utf-8")

msg_len = len(msg_bytes)

ad = b""  # No associated data

key = b"\x00" * 16

nonce = b"\x01" * 16

# Prepare buffers
msg_buf = (ctypes.c_ubyte * msg_len).from_buffer_copy(msg_bytes)

ad_buf = (ctypes.c_ubyte * len(ad))(*ad) if ad else None

key_buf = (ctypes.c_ubyte * 16).from_buffer_copy(key)


cipher_len = ctypes.c_ulonglong(msg_len + 16)

cipher_buf = (ctypes.c_ubyte * cipher_len.value)()

try:
    os.makedirs(KEY_DIR, exist_ok=True)

    if not os.path.exists(pubkey_path) or not os.path.exists(seckey_path):

        tracemalloc.start()
        start_keygen_time = time.perf_counter()  # Best for measuring short durations
        start_keygen_cycles = cycles.rdtsc()
        pk, sk = keygen()
        end_keygen_cycles = cycles.rdtsc()
        end_keygen_time = time.perf_counter()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        keygen_elapsed_time = end_keygen_time - start_keygen_time
        print(f"Elapsed time for ascon encryption: {keygen_elapsed_time:.6f} seconds")
        print(f"[Cycles] Ascon  encrypt cycle: {end_keygen_cycles - start_keygen_cycles} cycles")
        print(f"[Memory] Kyber keygen - Current: {current / 1024:.1f} KB | Peak: {peak / 1024:.1f} KB")
        print("[INFO] Generating new Kyber keypair...")
        with open(pubkey_path, "wb") as f:
            f.write(pk)
        with open(seckey_path, "wb") as f:
            f.write(sk)
    else:
        print("[INFO] Loading existing Kyber keys...")
        with open(pubkey_path, "rb") as f:
            pk = f.read()
            print("pk", pk)
        with open(seckey_path, "rb") as f:
            sk = f.read()
except Exception as e:
    print("[ERROR] Key generation error:", e)
    raise


@app.route("/")
def index():
    return render_template("index.html")

@app.route("/secure-ecg", methods=["POST"])
def secure_ecg():
    print("[SERVER] Received POST /secure-ecg")

    if not request.is_json:
        return "Expected JSON payload", 400

    data = request.get_json(force=True)
    nonce = base64.b64decode(data["nonce"])
    ciphertext = base64.b64decode(data["ciphertext"])
    kyber_ct = base64.b64decode(data["kyber_ciphertext"])
    print("server_raw_ct", kyber_ct)
    athlete_id = data["id"]
    # === Measure memory for Kyber decapsulation ===
    import tracemalloc
    tracemalloc.start()
    start_decaps_time = time.perf_counter()  # Best for measuring short durations
    start_decaps_cycles = cycles.rdtsc()
    shared_secret = decapsulate(kyber_ct, sk)
    end_decaps_cycles = cycles.rdtsc()
    end_decaps_time = time.perf_counter()  # Best for measuring short durations
    snapshot_decaps = tracemalloc.take_snapshot()
    top_decaps = snapshot_decaps.statistics('lineno')
    decaps_elapsed_time = end_decaps_time - start_decaps_time

    print("\n[Memory] Kyber decapsulation:")
    for i, stat in enumerate(top_decaps[:5], 1):
        print(f"{i}. {stat}")
    current, peak = tracemalloc.get_traced_memory()

    print(f"Elapsed time for decaps : {decaps_elapsed_time:.6f} seconds")
    print(f"[Cycles] decaps cycle: {end_decaps_cycles - start_decaps_cycles} cycles")
    print(f"[Peak Mem] Kyber decaps - Current: {current / 1024:.1f} KB | Peak: {peak / 1024:.1f} KB")
    tracemalloc.stop()
    key = shared_secret[:16]
    # === Measure memory for Ascon decryption ===
    tracemalloc.start()
    start_decrypt_time = time.perf_counter()  # Best for measuring short durations
    start_decrypt_cycles = cycles.rdtsc()
    # msg_out_buf = (ctypes.c_ubyte * msg_len)()
    # msg_out_len = ctypes.c_ulonglong(0)

    msg_out_buf = (ctypes.c_ubyte * len(ciphertext))()
    msg_out_len = ctypes.c_ulonglong(0)

    nonce_buf = (ctypes.c_ubyte * 16).from_buffer_copy(nonce)

    cipher_len = ctypes.c_ulonglong(len(ciphertext))
    cipher_buf = (ctypes.c_ubyte * cipher_len.value).from_buffer_copy(ciphertext)

    print("[INFO] Preparing decryption...")
    print("Shared secret (first 16 bytes):", shared_secret[:16].hex())
    print("Ciphertext length (decoded):", len(ciphertext))


    print("hhiii")
    dec_result = lib.crypto_aead_decrypt(msg_out_buf,
                                         ctypes.byref(msg_out_len),
                                         None,
                                         cipher_buf,
                                         cipher_len.value,
                                         ad_buf,
                                         len(ad) if ad else 0,
                                         nonce_buf,
                                         key_buf)

    print("bbb")


    decrypted = bytes(msg_out_buf[:msg_out_len.value])
    print(f"[Decryption] Success? {dec_result == 0}, Plaintext length: {msg_out_len.value} bytes")
    # Atempt to decode and print the string
    try:
        print("[Decrypted String]:", decrypted.decode('utf-8'))
    except UnicodeDecodeError as e:
        print("[Decrypted Bytes]:", decrypted)
        print("[Decode Error]:", e)
    end_decrypt_cycles = cycles.rdtsc()
    end_decrypt_time = time.perf_counter()  # Best for measuring short durations
    snapshot_decrypt = tracemalloc.take_snapshot()
    top_decrypt = snapshot_decrypt.statistics('lineno')
    print("\n[Memory] Ascon decryption:")
    for i, stat in enumerate(top_decrypt[:5], 1):
        print(f"{i}. {stat}")
    current, peak = tracemalloc.get_traced_memory()
    decrypt_elapsed_time = end_decrypt_time - start_decrypt_time
    print(f"Elapsed time for decrypt : {decrypt_elapsed_time:.6f} seconds")
    print(f"[Cycles] decrypt cycle: {end_decrypt_cycles - start_decrypt_cycles} cycles")
    print(f"[Peak Mem] Ascon decrypt - Current: {current / 1024:.1f} KB | Peak: {peak / 1024:.1f} KB")
    tracemalloc.stop()
    if decrypted is None:
        return "Decryption failed", 400

    records = json.loads(decrypted.decode())
    df = pd.DataFrame(records)
    athlete_dir = os.path.join(app.root_path, "static", f"athlete_{athlete_id}")
    os.makedirs(athlete_dir, exist_ok=True)
    save_path = os.path.join(athlete_dir, "decrypted_ecg.json")
    df.to_json(save_path, orient="records")
    print(f"[INFO] ECG data saved to {save_path}")
    return "ECG received and decrypted successfully", 200

@app.route("/kyber-public-key", methods=["GET"])
def get_kyber_pubkey():
    return send_file(pubkey_path, mimetype="application/octet-stream")




@app.route("/ecg-viewer")
def ecg_viewer():
    try:
        athlete_index = int(request.args.get("athlete", 1))
        athlete_index = max(1, min(athlete_index, 28))

        file_path = os.path.join(app.root_path, "static", f"athlete_{athlete_index}", "decrypted_ecg.json")
        if not os.path.exists(file_path):
            return f"❌ File not found: {file_path}", 404

        with open(file_path, "r") as f:
            records = json.load(f)
        df = pd.DataFrame(records)

        time = df['time'].to_numpy()
        all_leads = ['V6', 'V5', 'V4', 'V3', 'V2', 'V1', 'aVF', 'aVL', 'aVR', 'III', 'II', 'I']
        lead_names = [lead for lead in all_leads if lead in df.columns]
        vertical_offsets = np.arange(len(lead_names)) * 2
        lead_names = lead_names[::-1]
        vertical_offsets = vertical_offsets[::-1]

        fig = go.Figure()
        for i, lead in enumerate(lead_names):
            y = (df[lead].to_numpy() + vertical_offsets[i]).tolist()
            fig.add_trace(
                go.Scatter(x=time.tolist(), y=y, mode='lines', line=dict(color='black', width=1), showlegend=False))

        duration = time[-1] if len(time) > 0 else 0
        shapes = []
        for t in np.arange(0, duration + 0.2, 0.2):
            shapes.append(dict(type='line', x0=t, x1=t, y0=vertical_offsets[-1] - 2, y1=vertical_offsets[0] + 2,
                               line=dict(color='rgba(255,0,0,0.5)', width=0.8)))
        for y in np.arange(vertical_offsets[-1] - 2, vertical_offsets[0] + 2, 0.5):
            shapes.append(dict(type='line', x0=0, x1=duration, y0=y, y1=y,
                               line=dict(color='rgba(255,0,0,0.5)', width=0.8)))

        fig.update_layout(
            title=f"12-Lead ECG Viewer: Athlete {athlete_index}",
            xaxis=dict(title="Time (seconds)", showgrid=False, zeroline=False),
            yaxis=dict(tickmode='array', tickvals=vertical_offsets, ticktext=lead_names, showgrid=False,
                       zeroline=False),
            shapes=shapes,
            template="simple_white",
            height=800,
            margin=dict(l=60, r=30, t=60, b=40)
        )

        return render_template("ecg_viewer.html",
                               graph_html=fig.to_html(full_html=False),
                               athlete_index=athlete_index,
                               prev_index=max(1, athlete_index - 1),
                               next_index=min(28, athlete_index + 1))
    except Exception as e:
        return f"❌ Failed to render ECG viewer: {e}", 500


@app.route('/receive-hl7', methods=['POST'])
def receive_hl7():
    hl7_msg = request.data.decode('utf-8')

    try:
        # Parse the HL7 message
        msg = parse_message(hl7_msg)

        # Extract data
        patient_id = msg.pid.pid_3.value
        patient_name = msg.pid.pid_5.value
        location = msg.pv1.pv1_3.value

        print("HLS 7 DATA REEIVED", {
            "PATIENT_ID": patient_id
        })

        return jsonify({
            "status": "Message received",
            "patient_id": patient_id,
            "patient_name": patient_name,
            "location": location
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/hl_secure-ecg', methods=['POST'])
def receive_encyrpted_hl7():
    hl7_msg = request.data.decode('utf-8')

    try:
        # Parse the HL7 message
        msg = parse_message(hl7_msg)

        print(
            msg.to_er7().replace("\r", "\n"))

        # Extract data
        # patient_id = msg.pid.pid_3.value
        # patient_name = msg.pid.pid_5.value
        # location = msg.pv1.pv1_3.value

        print("vvv", msg.obx.obx_5.value)

        print("HLS 7 DATA REEIVED", {
            "PATIENT_ID": "patient_id"

        })

        return jsonify({
            "status": "Message received",
            # "patient_id": patient_id,
            # "patient_name": patient_name,
            # "location": location
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


if __name__ == "__main__":
    print(f"[SERVER STARTED] Public Key Path: {pubkey_path}")
    app.run(host="0.0.0.0", port=5070, debug=True)

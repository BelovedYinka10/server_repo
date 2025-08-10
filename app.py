import os
import json
import numpy as np
import pandas as pd
import plotly.graph_objects as go
from flask import Flask, request, render_template, send_file, jsonify
from smaj_kyber import keygen, decapsulate, set_mode
from pyascon.ascon import ascon_decrypt
from hl7apy.parser import parse_message
from kyber_py.ml_kem import ML_KEM_512
import base64
import time

# import cycles  # Your custom rdtsc module
dt_format = os.getenv("DATA_FORMAT")

app = Flask(__name__)

# === Key Paths ===
KEY_DIR = os.path.join(app.root_path, "keys")
pubkey_path = os.path.join(KEY_DIR, "server_pubkey.bin")
seckey_path = os.path.join(KEY_DIR, "server_seckey.bin")
import tracemalloc  # Make sure this is imported at the top

# === Generate or Load Kyber Keys ===
import tracemalloc  # Make sure this is imported at the top

try:
    os.makedirs(KEY_DIR, exist_ok=True)

    if not os.path.exists(pubkey_path) or not os.path.exists(seckey_path):

        tracemalloc.start()
        start_keygen_time = time.perf_counter()  # Best for measuring short durations
        # start_keygen_cycles = cycles.rdtsc()
        pk, sk = ML_KEM_512.keygen()
        # end_keygen_cycles = cycles.rdtsc()
        end_keygen_time = time.perf_counter()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        keygen_elapsed_time = end_keygen_time - start_keygen_time
        print(f"Elapsed time for ascon encryption: {keygen_elapsed_time:.6f} seconds")
        # print(f"[Cycles] Ascon  encrypt cycle: {end_keygen_cycles - start_keygen_cycles} cycles")
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


@app.route("/kyber-public-key", methods=["GET"])
def get_kyber_pubkey():
    return send_file(pubkey_path, mimetype="application/octet-stream")


@app.route("/secure-ecg", methods=["POST"])
def secure_ecg():
    print("[SERVER] Received POST /secure-ecg")

    if not request.is_json:
        return "Expected JSON payload", 400

    data = request.get_json(force=True)

    nonce = base64.b64decode(data["nonce"])
    ciphertext = base64.b64decode(data["ciphertext"])
    kyber_ct = base64.b64decode(data["kyber_ciphertext"])
    dt_format = data.get("dt_format", "JSON")

    print("server_raw_ct", kyber_ct)

    athlete_id = data["id"]

    # === Measure memory for Kyber decapsulation ===
    import tracemalloc
    import time
    tracemalloc.start()
    start_decaps_time = time.perf_counter()
    shared_secret = ML_KEM_512.decaps(sk, kyber_ct)
    end_decaps_time = time.perf_counter()
    decaps_elapsed_time = end_decaps_time - start_decaps_time
    current, peak = tracemalloc.get_traced_memory()
    print(f"[Peak Mem] Kyber decaps - Current: {current / 1024:.1f} KB | Peak: {peak / 1024:.1f} KB")
    tracemalloc.stop()

    key = shared_secret[:16]

    # === Measure memory for Ascon decryption ===
    tracemalloc.start()
    start_decrypt_time = time.perf_counter()
    decrypted = ascon_decrypt(key=key, nonce=nonce, ciphertext=ciphertext, associateddata=b"")
    end_decrypt_time = time.perf_counter()
    decrypt_elapsed_time = end_decrypt_time - start_decrypt_time
    current, peak = tracemalloc.get_traced_memory()
    print(f"[Peak Mem] Ascon decrypt - Current: {current / 1024:.1f} KB | Peak: {peak / 1024:.1f} KB")
    tracemalloc.stop()

    if decrypted is None:
        return "Decryption failed", 400

    decrypted_str = decrypted.decode()

    try:
        if dt_format.upper() == "XML":
            from xml.etree import ElementTree as ET
            root = ET.fromstring(decrypted_str)
            records = [{child.tag: child.text for child in record} for record in root.findall("Record")]
        else:
            import json
            records = json.loads(decrypted_str)
    except Exception as e:
        return f"Failed to parse decrypted payload: {e}", 400

    # === Save both encrypted and decrypted ECG ===
    import pandas as pd
    import os
    athlete_dir = os.path.join(app.root_path, "static", f"athlete_{athlete_id}")
    os.makedirs(athlete_dir, exist_ok=True)

    # Save encrypted file
    enc_path = os.path.join(athlete_dir, "encrypted_ecg.enc")
    with open(enc_path, "wb") as f:
        f.write(ciphertext)
    print(f"[INFO] Encrypted ECG saved to {enc_path}")

    # Save decrypted file
    save_path = os.path.join(athlete_dir, "decrypted_ecg.json")
    df = pd.DataFrame(records)
    df.to_json(save_path, orient="records")
    print(f"[INFO] Decrypted ECG saved to {save_path}")

    return "ECG received, saved, and decrypted successfully", 200


@app.route("/ecg-viewer")
def ecg_viewer():
    try:
        athlete_index = int(request.args.get("athlete", 1))
        athlete_index = max(1, min(athlete_index, 28))

        # if dt_format.upper() == "XML":
        file_path = os.path.join(app.root_path, "static", f"athlete_{athlete_index}", "decrypted_ecg.json")
        # else:
        #     file_path = os.path.join(app.root_path, "static", f"athlete_{athlete_index}", "decrypted_ecg.xml")

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

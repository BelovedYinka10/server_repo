# server.py
import numpy as np
from flask import Flask, request, render_template, send_file
from smaj_kyber import keygen, decapsulate, set_mode
from pyascon.ascon import ascon_decrypt
import pandas as pd
import json
import os
from smaj_kyber import keygen, decapsulate, set_mode
from pyascon.ascon import ascon_decrypt
import pandas as pd
import json
import os
import numpy as np
import plotly.graph_objects as go

app = Flask(__name__)

# === Set Kyber Mode ===
set_mode("512")

# === Key File Paths ===
KEY_DIR = ".\keys"
pubkey_path = os.path.join(KEY_DIR, "server_pubkey.bin")
seckey_path = os.path.join(KEY_DIR, "server_seckey.bin")

# === Create Key Folder and Generate/Load Keys ===
try:
    os.makedirs(KEY_DIR, exist_ok=True)

    print("pubkey_path", pubkey_path)
    print("seckey_path", seckey_path)

    if not os.path.exists(pubkey_path) or not os.path.exists(seckey_path):
        print("[INFO] Key files not found. Generating Kyber keypair...")
        pk, sk = keygen()

        with open(pubkey_path, "wb") as f:
            f.write(pk)

        with open(seckey_path, "wb") as f:
            f.write(sk)
        print("[INFO] Kyber keypair generated and saved.")

    else:
        print("[INFO] Loading existing Kyber keys...")
        with open(pubkey_path, "rb") as f:
            pk = f.read()
        with open(seckey_path, "rb") as f:
            sk = f.read()
        print("[INFO] Kyber keys loaded successfully.")
except Exception as e:
    print("[ERROR] Failed during keypair setup:", e)
    raise


@app.route("/")
def index():
    return "Secure ECG Server is Running"


@app.route("/kyber-public-key", methods=["GET"])
def get_kyber_pubkey():
    return send_file(pubkey_path, mimetype="application/octet-stream")


@app.route("/secure-ecg", methods=["POST"])
def secure_ecg():
    print("[SERVER] Received POST /secure-ecg")
    print("Headers:", dict(request.headers))
    print("Content-Type:", request.content_type)

    # Check if JSON is received properly
    if not request.is_json:
        print("[ERROR] Content-Type is not application/json")
        return "Invalid content type. Expected application/json", 403

    try:
        data = request.get_json(force=True)  # Force parsing even if header missing
        print("[SERVER] JSON parsed successfully")
        print("Keys in data:", list(data.keys()))

        # Parse hex fields
        nonce = bytes.fromhex(data["nonce"])
        ciphertext = bytes.fromhex(data["ciphertext"])
        kyber_ct = bytes.fromhex(data["kyber_ciphertext"])

        shared_secret = decapsulate(kyber_ct, sk)
        key = shared_secret[:16]

        decrypted = ascon_decrypt(key=key, nonce=nonce, ciphertext=ciphertext, associateddata=b"")
        if decrypted is None:
            print("[ERROR] Ascon decryption returned None")
            return "Decryption failed: possibly incorrect key/nonce/ciphertext", 400

        print("[SERVER] Ascon decryption successful")

        records = json.loads(decrypted.decode())

        df = pd.DataFrame(records)

        os.makedirs("static", exist_ok=True)
        df.to_json("static/decrypted_ecg.json", orient="records")

        print("[SERVER] ECG DataFrame preview:")
        print(df.head())

        return "ECG received and decrypted successfully", 200

    except Exception as e:
        print("[ERROR] Exception occurred:", str(e))
        return f"Error: {e}", 400


@app.route("/ecg-viewer")
def ecg_viewer():
    try:
        with open("static/decrypted_ecg.json", "r") as f:
            records = json.load(f)
        df = pd.DataFrame(records)

        time = df['time'].to_numpy()
        all_possible_leads = ['V6', 'V5', 'V4', 'V3', 'V2', 'V1', 'aVF', 'aVL', 'aVR', 'III', 'II', 'I']

        # Filter only leads that exist in the DataFrame
        lead_names = [lead for lead in all_possible_leads if lead in df.columns]
        vertical_offsets = np.arange(len(lead_names)) * 2
        lead_names = lead_names[::-1]
        vertical_offsets = vertical_offsets[::-1]

        # Plot
        fig = go.Figure()
        x = time.tolist()
        for i, lead in enumerate(lead_names):
            y = (df[lead].to_numpy() + vertical_offsets[i]).tolist()
            fig.add_trace(go.Scatter(
                x=x,
                y=y,
                mode='lines',
                name=lead,
                line=dict(color='black', width=1),
                showlegend=False
            ))

        # Grid lines
        duration_sec = time[-1] if len(time) > 0 else 0
        shapes = []
        grid_color = 'rgba(255, 0, 0, 0.5)'
        for t in np.arange(0, duration_sec + 0.2, 0.2):
            shapes.append(dict(type='line', x0=t, x1=t, y0=vertical_offsets[-1] - 2, y1=vertical_offsets[0] + 2,
                               line=dict(color=grid_color, width=0.8)))
        for y in np.arange(vertical_offsets[-1] - 2, vertical_offsets[0] + 2, 0.5):
            shapes.append(dict(type='line', x0=0, x1=duration_sec, y0=y, y1=y, line=dict(color=grid_color, width=0.8)))

        fig.update_layout(
            title="12-Lead ECG Viewer (Clinical Layout)",
            xaxis=dict(title="Time (seconds)", showgrid=False, zeroline=False),
            yaxis=dict(
                tickmode='array',
                tickvals=vertical_offsets,
                ticktext=lead_names,
                showgrid=False,
                zeroline=False
            ),
            shapes=shapes,
            template="simple_white",
            height=800,
            margin=dict(l=60, r=30, t=60, b=40)
        )

        return render_template("ecg_viewer.html", graph_html=fig.to_html(full_html=False))

    except Exception as e:
        return f"❌ Failed to render ECG viewer: {e}", 500


if __name__ == "__main__":
    print(f"[SERVER STARTED] Public Key Path: {pubkey_path}")
    app.run(host="0.0.0.0", port=5000, debug=True)


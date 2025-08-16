
```markdown
# 🩺 Secure ECG Transmission & Reception — Kyber + Ascon + HL7

This project demonstrates **end-to-end secure transmission and visualization of ECG data** using a hybrid cryptographic approach:
- **Kyber512** — post-quantum secure key encapsulation  
- **Ascon-128** — lightweight authenticated encryption  
- **HL7 v2.5** — medical message formatting for interoperability

It includes:
1. **Client-side script** to acquire, encrypt, and send ECG data.
2. **Server-side Flask application** to receive, decrypt, store, and visualize ECG data.

---

## 🚀 End-to-End Workflow

### 1️⃣ Key Exchange (Kyber512)
- **Server** generates a Kyber keypair (`server_pubkey.bin`, `server_seckey.bin`) and makes the public key available at:
```

GET /kyber-public-key

```
- **Client** retrieves this key and performs **Kyber encapsulation** to produce:
  - Ciphertext (`kyber_ciphertext`)
  - Shared secret (`shared_secret`)
- **Client** truncates the shared secret to 16 bytes for **Ascon-128** encryption.

---

### 2️⃣ ECG Data Acquisition (Client)
- Reads ECG data from PhysioNet’s **Norwegian Endurance Athlete ECG dataset** using WFDB.
- Normalizes lead names, adds timestamps.
- Converts to JSON or XML depending on configuration.

---

### 3️⃣ Encryption (Client)
- Uses **Ascon-128** with:
  - Key = first 16 bytes of `shared_secret`
  - Nonce = fixed 16-byte value (`12345678abcdef12`)
  - Associated data = `"MacBook"` (example)
- Saves encrypted ECG to:
```

/Desktop/secure by design/norway/cg/ecg\_<timestamp>.enc

```

---

### 4️⃣ HL7 Message Construction (Client)
- Builds an **ORU^R01** HL7 message with:
  - OBX segment for encrypted ECG file
  - OBX segment for nonce
  - OBX segment for Kyber ciphertext

---

### 5️⃣ Secure Transmission (Client → Server)
- Sends HL7 or JSON payload to:
```

POST /secure-ecg

````
- **Content**:
```json
{
  "nonce": "<Base64>",
  "ciphertext": "<Base64>",
  "kyber_ciphertext": "<Base64>",
  "id": "athlete_id",
  "dt_format": "JSON"
}
````

---

### 6️⃣ Decryption & Storage (Server)

* Decapsulates Kyber ciphertext with `ML_KEM_512.decaps()` using private key.
* Derives Ascon key from shared secret.
* Decrypts ECG payload with `ascon_decrypt`.
* Parses JSON/XML into Pandas DataFrame.
* Saves to:

```
static/athlete_<id>/decrypted_ecg.json
```

---

### 7️⃣ Visualization (Server)

* Endpoint:

```
GET /ecg-viewer?athlete=<id>
```

* Renders interactive **12-lead ECG plot** with Plotly.
* Displays red gridlines at medical standard intervals.

---

### 8️⃣ HL7 Support (Server)

* `/receive-hl7` — parse plain HL7 messages, extract patient details.
* `/hl_secure-ecg` — parse HL7 messages containing encrypted payloads.

---


## ⚙️ Requirements

### how to run code:

```bash
python 3.11 is required 
steps to follow to run the http 

1) python3 -m venv venv 
2) activate the venv
3) pip install -r requirement.txt
4) python3 app.py # USE THIS FOR THE HTTP 
5) go to the url
```

```bash
python 3.11 is required 
steps to follow to run the mllp 

1) python3 -m venv venv 
2) activate the venv
3) pip install -r requirement.txt
5) python mllp_hl7_server_app.py # this starts MLLP server
```


Custom modules:

* `smaj_kyber` — Kyber wrapper
* `kyber_py.ml_kem` — Python Kyber implementation

---

## 🧪 Example Run

**Client Output:**

```
[INFO] Received Kyber public key from server.
[INFO] ECG data encrypted with Ascon.
Status Code: 200
Server response: ECG message successfully received and processed.
```

**Server Output:**

```
[INFO] Loading existing Kyber keys...
[SERVER] Received POST /secure-ecg
[Memory] Kyber decapsulation: Peak: 19.3 KB
Elapsed time for decaps: 0.000821 seconds
[Memory] Ascon decryption: Peak: 16.1 KB
Elapsed time for decrypt: 0.000514 seconds
[INFO] ECG data saved to static/athlete_1/decrypted_ecg.json
```

---

## 📌 Notes

* Designed for **Medical IoT** scenarios and NHS-compatible devices.
* Prototype implementation — **C reference** crypto implementations used, not optimized for Cortex-M microcontrollers.
* HL7 handling is minimal — production use requires ACK responses and validation.

```

---

If you paste this into your `README.md`, you’ll have a **full client + server doc** in one place.  

Do you want me to also **embed a diagram** showing the entire encryption/decryption data flow? That would make it easier for reviewers to follow.
```


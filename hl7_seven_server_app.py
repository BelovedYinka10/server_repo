from flask import Flask, request, jsonify
from hl7apy.parser import parse_message

app = Flask(__name__)

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


        print("HLS 7 DATA REEIVED",{
            "PATIENT_ID" :  patient_id
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
def receive_hl7():
    hl7_msg = request.data.decode('utf-8')
    
    try:
        # Parse the HL7 message
        msg = parse_message(hl7_msg)
        
        # Extract data
        patient_id = msg.pid.pid_3.value
        patient_name = msg.pid.pid_5.value
        location = msg.pv1.pv1_3.value


        print("HLS 7 DATA REEIVED",{
            "PATIENT_ID" :  patient_id
        })
        
        return jsonify({
            "status": "Message received",
            "patient_id": patient_id,
            "patient_name": patient_name,
            "location": location
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)


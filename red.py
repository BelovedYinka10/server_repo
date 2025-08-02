import serial

ser = serial.Serial('COM6', 9600)
print("[WINDOWS SERVER] Listening on COM6...")

while True:
    if ser.in_waiting > 0:
        msg = ser.readline().decode('utf-8').strip()
        print("[RECEIVED]", msg)

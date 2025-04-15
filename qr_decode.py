import cv2
import qrcode
import base64
from pyzbar.pyzbar import decode
from PIL import Image

# Function to generate QR code from a file
def generate_qr_from_file(file_path, output_qr="qrcode.png"):
    try:
        with open(file_path, "rb") as file:
            file_data = file.read()
        
        # Encode file content in Base64
        encoded_data = base64.b64encode(file_data).decode('utf-8')
        
        # Generate QR Code
        qr = qrcode.QRCode(version=5, box_size=10, border=5)
        qr.add_data(encoded_data)
        qr.make(fit=True)
        qr_image = qr.make_image(fill="black", back_color="white")
        qr_image.save(output_qr)
        qr_image.show()

        print(f"✅ QR Code saved as {output_qr}")
    except Exception as e:
        print(f"❌ Error: {e}")

# Function to scan QR code from webcam and decode data
def scan_qr_from_webcam():
    cap = cv2.VideoCapture(0)  # Open the webcam
    print("📷 Point your webcam at a QR code...")

    while True:
        ret, frame = cap.read()  # Capture frame
        if not ret:
            continue

        decoded_objects = decode(frame)  # Decode QR from frame

        for obj in decoded_objects:
            qr_data = obj.data.decode('utf-8')  # Extract data
            cap.release()
            cv2.destroyAllWindows()

            print("✅ QR Code Detected! Decoding data...")
            try:
                # Decode Base64 data
                file_data = base64.b64decode(qr_data)

                # Save recovered data
                with open("recovered_file.txt", "wb") as file:
                    file.write(file_data)

                print("📂 File successfully recovered as 'recovered_file.txt'!")
                return "File recovered successfully!"
            except:
                print("🔗 It looks like a URL or text:", qr_data)
                return qr_data

        cv2.imshow("QR Scanner", frame)

        if cv2.waitKey(1) & 0xFF == ord('q'):  # Press 'q' to quit
            break

    cap.release()
    cv2.destroyAllWindows()

# Example Usage
# 1️⃣ Generate a QR from a file
generate_qr_from_file("example.txt")

# 2️⃣ Scan and decode from webcam
scan_qr_from_webcam()

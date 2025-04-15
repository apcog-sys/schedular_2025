import qrcode
import base64

def generate_qr_from_file(file_path, output_qr="qrcode.png"):
    try:
        # Read file data
        with open(file_path, "rb") as file:
            file_data = file.read()
        
        # Encode file data in Base64 to avoid corruption
        encoded_data = base64.b64encode(file_data).decode('utf-8')
        
        # Generate QR Code
        qr = qrcode.QRCode(version=5, box_size=10, border=5)
        qr.add_data(encoded_data)
        qr.make(fit=True)

        # Convert to Image
        qr_image = qr.make_image(fill="black", back_color="white")
        qr_image.save(output_qr)
        qr_image.show()

        print(f"✅ QR Code saved as {output_qr}")
    except Exception as e:
        print(f"❌ Error: {e}")

# Example Usage
file_path = "example.txt"  # Replace with your file
generate_qr_from_file(file_path)

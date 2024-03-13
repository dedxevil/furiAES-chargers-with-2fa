from flask import Flask, request, render_template
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import pyotp
import hashlib
from flask_cors import CORS, cross_origin

app = Flask(__name__)
app.config['CORS_HEADERS'] = 'Content-Type'

cors = CORS(app, resources={r"/decrypt": {"origins": "http://localhost:5000"}})

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/encrypt", methods=["POST"])
@cross_origin(origin='localhost',headers=['Content- Type','Authorization'])
def encrypt():
    file = request.files["file"]
    password = request.form["password"]

    # Read file contents
    file_contents = file.read()

    # Encrypt file contents
    hashed_password = hashlib.sha256(password.encode()).digest()
    cipher = Cipher(algorithms.AES(hashed_password), modes.CBC(b'\x00' * 16), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(file_contents) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Save encrypted data to a file or database
    with open("encrypted_file.txt", "wb") as encrypted_file:
        encrypted_file.write(encrypted_data)

    return "File encrypted successfully"

@app.route("/decrypt", methods=["POST"])
@cross_origin(origin='localhost',headers=['Content- Type','Authorization'])
def decrypt():
    print(request.headers.get('dp'))
    encrypted_file = request.files["encrypted_file"]
    decryption_password = request.form["decryption_password"]
    otp = request.form["otp"]

    hashed_password = hashlib.sha256(decryption_password.encode()).digest()
    # Read encrypted file contents
    # with open(encrypted_file,encoding="utf-8",errors='ignore') as f:
    encrypted_file_contents = encrypted_file.read()

    # Decrypt file contents
    cipher = Cipher(algorithms.AES(hashed_password), modes.CBC(b'\x00' * 16), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_file_contents) + decryptor.finalize()

    # Remove padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    # Verify OTP
    print(request.headers.get('dp'))
    otp_uri = "otpauth://totp/AES%20Demo?secret=" + request.headers.get('dp')
    # totp = pyotp.TOTP(request.headers.get('dp'))#.provisioning_uri(issuer_name='AES Demo')
    totp = pyotp.parse_uri( otp_uri )
    print(totp)
    if not totp.verify(otp):
        return "Invalid OTP : " + "OTP =--= " + otp + "3434" + request.headers.get('dp') + " -- " + totp.now()

    # Display or save decrypted data
    decrypted_file_path = "decrypted_file.txt"
    with open(decrypted_file_path, "wb") as decrypted_file:
        decrypted_file.write(unpadded_data)

    return "File decrypted successfully"

if __name__ == "__main__":
    app.run(debug=True)

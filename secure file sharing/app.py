from flask import Flask, render_template, request, send_file
from Crypto.Cipher import AES
import os

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
KEY_FILE = "secret.key"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def load_key():
    return open(KEY_FILE, "rb").read()

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        file = request.files["file"]
        data = file.read()

        key = load_key()
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)

        filename = file.filename + ".enc"
        with open(os.path.join(UPLOAD_FOLDER, filename), "wb") as f:
            f.write(cipher.nonce + tag + ciphertext)

        return "File encrypted & uploaded successfully"

    return render_template("index.html")

@app.route("/download/<filename>")
def download(filename):
    key = load_key()

    with open(os.path.join(UPLOAD_FOLDER, filename), "rb") as f:
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()

    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)

    output = filename.replace(".enc", "")
    with open(output, "wb") as f:
        f.write(data)

    return send_file(output, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)
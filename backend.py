from flask import Flask, request, jsonify, render_template
import re
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

app = Flask(__name__)

# Function to check password length
def check_length(password):
    if len(password) >= 12:
        return True
    return False

# Function to check if password contains a mix of uppercase, lowercase, numbers, and special characters
def check_complexity(password):
    if (re.search(r'[A-Z]', password) and
        re.search(r'[a-z]', password) and
        re.search(r'[0-9]', password) and
        re.search(r'[@$!%*?&]', password)):
        return True
    return False

# Function to check if password is a dictionary word or common pattern
def check_common_patterns(password):
    common_words = ["password", "123456", "qwerty", "abc123", "letmein"]
    for word in common_words:
        if word in password:
            return False
    return True

# Function to hash password using SHA256
def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

# Function to encrypt password using AES
def encrypt_password(password):
    key = b'Sixteen byte key'
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted = cipher.encrypt(pad(password.encode('utf-8'), AES.block_size))
    return encrypted.hex()

# Route to check password strength
@app.route('/check_password', methods=['POST'])
def check_password_strength():
    data = request.json
    password = data.get('password')

    if not check_length(password):
        return jsonify({'error': 'Password must be at least 12 characters long.'}), 400

    if not check_complexity(password):
        return jsonify({'error': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.'}), 400

    if not check_common_patterns(password):
        return jsonify({'error': 'Password contains common or easily guessable patterns.'}), 400

    hashed_password = hash_password(password)
    encrypted_password = encrypt_password(password)

    return jsonify({
        'strength': 'Strong password!',
        'hashed_password': hashed_password,
        'encrypted_password': encrypted_password
    })

# Route to serve the HTML page
@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)

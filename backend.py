from flask import Flask, request, jsonify, render_template
import re
import hashlib
import secrets
import time
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

app = Flask(__name__)

# Cyberpunk-themed security messages
CYBERPUNK_MESSAGES = {
    'init': [
        "CYBERPUNK SECURITY PROTOCOL v2.0 INITIALIZED",
        "NEURAL NETWORK SCANNING ACTIVE",
        "QUANTUM ENCRYPTION MATRIX ONLINE",
        "DIGITAL FORTRESS SECURITY ENGAGED"
    ],
    'secure': [
        "MAXIMUM ENCRYPTION ACHIEVED - SYSTEM SECURE",
        "QUANTUM BARRIER ESTABLISHED - BREACH IMPOSSIBLE",
        "NEURAL FIREWALL ACTIVE - UNAUTHORIZED ACCESS DENIED",
        "CYBERPUNK SECURITY PROTOCOL: MAXIMUM DEFENSE"
    ],
    'breach': [
        "SECURITY BREACH DETECTED - IMMEDIATE ACTION REQUIRED",
        "NEURAL NETWORK COMPROMISED - CRITICAL VULNERABILITY",
        "QUANTUM BARRIER FAILED - SYSTEM EXPOSED",
        "CYBERPUNK ALERT: SECURITY PROTOCOL BREACHED"
    ],
    'partial': [
        "PARTIAL SECURITY DETECTED - VULNERABILITIES IDENTIFIED",
        "NEURAL FIREWALL WEAKENED - ENHANCEMENT REQUIRED",
        "QUANTUM ENCRYPTION INCOMPLETE - RISK ASSESSMENT",
        "CYBERPUNK STATUS: SECURITY LEVEL INSUFFICIENT"
    ]
}

# Advanced cyberpunk security protocols
def neural_network_analysis(password):
    """Advanced neural network analysis for password strength"""
    analysis = {
        'entropy': calculate_entropy(password),
        'pattern_detection': detect_patterns(password),
        'vulnerability_score': 0,
        'security_level': 'CRITICAL'
    }
    
    # Calculate vulnerability score
    if len(password) < 8:
        analysis['vulnerability_score'] += 40
    elif len(password) < 12:
        analysis['vulnerability_score'] += 20
    
    if not re.search(r'[A-Z]', password):
        analysis['vulnerability_score'] += 15
    if not re.search(r'[a-z]', password):
        analysis['vulnerability_score'] += 15
    if not re.search(r'[0-9]', password):
        analysis['vulnerability_score'] += 15
    if not re.search(r'[@$!%*?&]', password):
        analysis['vulnerability_score'] += 15
    
    # Determine security level
    if analysis['vulnerability_score'] <= 10:
        analysis['security_level'] = 'MAXIMUM'
    elif analysis['vulnerability_score'] <= 30:
        analysis['security_level'] = 'HIGH'
    elif analysis['vulnerability_score'] <= 60:
        analysis['security_level'] = 'MODERATE'
    else:
        analysis['security_level'] = 'CRITICAL'
    
    return analysis

def calculate_entropy(password):
    """Calculate password entropy for security assessment"""
    charset_size = 0
    if re.search(r'[a-z]', password):
        charset_size += 26
    if re.search(r'[A-Z]', password):
        charset_size += 26
    if re.search(r'[0-9]', password):
        charset_size += 10
    if re.search(r'[@$!%*?&]', password):
        charset_size += 8
    
    if charset_size == 0:
        return 0
    
    entropy = len(password) * (charset_size ** 0.5)
    return round(entropy, 2)

def detect_patterns(password):
    """Detect common patterns and vulnerabilities"""
    patterns = []
    
    # Sequential patterns
    if re.search(r'(123|abc|qwe)', password.lower()):
        patterns.append('SEQUENTIAL_PATTERN_DETECTED')
    
    # Repeated characters
    if re.search(r'(.)\1{2,}', password):
        patterns.append('REPEATED_CHARACTERS_DETECTED')
    
    # Common substitutions
    common_subs = ['@', '3', '0', '1', '!', '$']
    for sub in common_subs:
        if sub in password:
            patterns.append('COMMON_SUBSTITUTION_DETECTED')
            break
    
    return patterns

def quantum_encryption(password):
    """Advanced quantum encryption with random key generation"""
    key = get_random_bytes(32)  # 256-bit key
    iv = get_random_bytes(16)   # 128-bit IV
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(password.encode('utf-8'), AES.block_size))
    
    return {
        'encrypted_data': encrypted.hex(),
        'key_hash': hashlib.sha256(key).hexdigest(),
        'iv': iv.hex(),
        'encryption_method': 'QUANTUM_AES_256_CBC'
    }

def neural_hash(password):
    """Multi-layer neural hashing with salt"""
    salt = secrets.token_hex(16)
    salted_password = password + salt
    
    # Multiple hash layers
    layer1 = hashlib.sha256(salted_password.encode()).hexdigest()
    layer2 = hashlib.sha512(layer1.encode()).hexdigest()
    layer3 = hashlib.blake2b(layer2.encode()).hexdigest()
    
    return {
        'neural_hash': layer3,
        'salt': salt,
        'hash_layers': 3,
        'algorithm': 'NEURAL_SHA256_SHA512_BLAKE2B'
    }

# Legacy functions with cyberpunk enhancements
def check_length(password):
    """Quantum length analysis protocol"""
    return len(password) >= 12

def check_complexity(password):
    """Neural complexity analysis"""
    return (re.search(r'[A-Z]', password) and
            re.search(r'[a-z]', password) and
            re.search(r'[0-9]', password) and
            re.search(r'[@$!%*?&]', password))

def check_common_patterns(password):
    """Advanced pattern recognition system"""
    common_words = [
        "password", "123456", "qwerty", "abc123", "letmein",
        "admin", "root", "user", "login", "welcome",
        "cyberpunk", "hacker", "matrix", "neon", "future"
    ]
    
    password_lower = password.lower()
    for word in common_words:
        if word in password_lower:
            return False
    return True

def hash_password(password):
    """Legacy hash function"""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def encrypt_password(password):
    """Legacy encryption function"""
    key = b'Sixteen byte key'
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted = cipher.encrypt(pad(password.encode('utf-8'), AES.block_size))
    return encrypted.hex()

# Cyberpunk API Routes
@app.route('/neural_analysis', methods=['POST'])
def neural_analysis():
    """Advanced neural network password analysis"""
    data = request.json
    password = data.get('password')
    
    if not password:
        return jsonify({
            'error': 'NEURAL NETWORK ERROR: NO TARGET PASSWORD DETECTED',
            'status': 'FAILED',
            'timestamp': time.time()
        }), 400
    
    # Perform neural network analysis
    analysis = neural_network_analysis(password)
    quantum_data = quantum_encryption(password)
    neural_data = neural_hash(password)
    
    # Select appropriate cyberpunk message
    if analysis['security_level'] == 'MAXIMUM':
        message = random.choice(CYBERPUNK_MESSAGES['secure'])
    elif analysis['security_level'] in ['HIGH', 'MODERATE']:
        message = random.choice(CYBERPUNK_MESSAGES['partial'])
    else:
        message = random.choice(CYBERPUNK_MESSAGES['breach'])
    
    return jsonify({
        'neural_analysis': analysis,
        'quantum_encryption': quantum_data,
        'neural_hash': neural_data,
        'cyberpunk_message': message,
        'security_protocol': 'NEURAL_NETWORK_v2.0',
        'timestamp': time.time(),
        'session_id': secrets.token_hex(16)
    })

@app.route('/quantum_encrypt', methods=['POST'])
def quantum_encrypt():
    """Quantum encryption endpoint"""
    data = request.json
    password = data.get('password')
    
    if not password:
        return jsonify({
            'error': 'QUANTUM ERROR: NO DATA TO ENCRYPT',
            'status': 'FAILED'
        }), 400
    
    encrypted_data = quantum_encryption(password)
    
    return jsonify({
        'quantum_encryption': encrypted_data,
        'status': 'SUCCESS',
        'message': 'QUANTUM ENCRYPTION COMPLETE',
        'timestamp': time.time()
    })

@app.route('/security_scan', methods=['POST'])
def security_scan():
    """Comprehensive security scan"""
    data = request.json
    password = data.get('password')
    
    if not password:
        return jsonify({
            'error': 'SECURITY SCAN FAILED: NO TARGET IDENTIFIED',
            'status': 'FAILED'
        }), 400
    
    # Comprehensive analysis
    analysis = neural_network_analysis(password)
    patterns = detect_patterns(password)
    entropy = calculate_entropy(password)
    
    # Security recommendations
    recommendations = []
    if analysis['vulnerability_score'] > 30:
        recommendations.append('INCREASE PASSWORD LENGTH TO 16+ CHARACTERS')
    if not re.search(r'[@$!%*?&]', password):
        recommendations.append('ADD SPECIAL SYMBOLS FOR ENHANCED SECURITY')
    if patterns:
        recommendations.append('AVOID COMMON PATTERNS AND SEQUENCES')
    
    return jsonify({
        'security_scan': {
            'vulnerability_score': analysis['vulnerability_score'],
            'security_level': analysis['security_level'],
            'entropy': entropy,
            'patterns_detected': patterns,
            'recommendations': recommendations
        },
        'status': 'SCAN_COMPLETE',
        'timestamp': time.time()
    })

# Legacy route for backward compatibility
@app.route('/check_password', methods=['POST'])
def check_password_strength():
    """Legacy password strength checker with cyberpunk enhancements"""
    data = request.json
    password = data.get('password')

    if not check_length(password):
        return jsonify({
            'error': 'QUANTUM LENGTH PROTOCOL FAILED: MINIMUM 12 CHARACTERS REQUIRED',
            'status': 'SECURITY_BREACH'
        }), 400

    if not check_complexity(password):
        return jsonify({
            'error': 'NEURAL COMPLEXITY ANALYSIS FAILED: INSUFFICIENT CHARACTER DIVERSITY',
            'status': 'SECURITY_BREACH'
        }), 400

    if not check_common_patterns(password):
        return jsonify({
            'error': 'PATTERN RECOGNITION ALERT: COMMON PATTERNS DETECTED',
            'status': 'SECURITY_BREACH'
        }), 400

    # Enhanced security processing
    hashed_password = hash_password(password)
    encrypted_password = encrypt_password(password)
    neural_data = neural_hash(password)
    
    return jsonify({
        'strength': 'NEURAL NETWORK: MAXIMUM SECURITY ACHIEVED',
        'hashed_password': hashed_password,
        'encrypted_password': encrypted_password,
        'neural_hash': neural_data,
        'cyberpunk_message': random.choice(CYBERPUNK_MESSAGES['secure']),
        'security_protocol': 'LEGACY_COMPATIBLE_v2.0'
    })

@app.route('/')
def index():
    """Main cyberpunk interface"""
    return render_template('index.html')

@app.route('/system_status')
def system_status():
    """System status endpoint"""
    return jsonify({
        'system': 'CYBERPUNK SECURITY PROTOCOL v2.0',
        'status': 'ONLINE',
        'neural_network': 'ACTIVE',
        'quantum_encryption': 'READY',
        'security_level': 'MAXIMUM',
        'timestamp': time.time(),
        'uptime': 'NEURAL_NETWORK_ACTIVE'
    })

if __name__ == '__main__':
    print("INITIALIZING CYBERPUNK SECURITY PROTOCOL v2.0...")
    print("NEURAL NETWORK: ONLINE")
    print("QUANTUM ENCRYPTION: READY")
    print("SECURITY MATRIX: ACTIVE")
    app.run(debug=True, host='0.0.0.0', port=5000)

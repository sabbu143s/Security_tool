import os
import json
import uuid
import base64
import mimetypes
import datetime
import jwt
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

# Import shared logic for static masking
from masking_logic import mask_data_recursively

# Imports for Encryption/Decryption
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

app = Flask(__name__)
CORS(app)

# --- Configuration ---
app.config['SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'a-very-strong-default-secret-for-development')
ADMIN_API_KEY = os.getenv('ADMIN_API_KEY', 'default-super-secret-admin-key')
USERS_FILE = 'users.json'
RULES_FILE = 'masking_rules.json'
DATA_FILE = 'encrypted_data.json'
ENCRYPTED_FILES_DIR = './encrypted_files'

# --- Helper Functions ---
def load_json_file(filepath):
    """Safely loads data from a JSON file."""
    if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
        return []
    with open(filepath, 'r') as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []

def save_json_file(data, filepath):
    """Saves data to a JSON file."""
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)

def sanitize_pem_key(pem_string):
    """A robust function to clean and reformat a PEM public key string."""
    key_body = pem_string.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replace("\n", "").strip()
    reformatted_key = "\n".join(key_body[i:i+64] for i in range(0, len(key_body), 64))
    return f"-----BEGIN PUBLIC KEY-----\n{reformatted_key}\n-----END PUBLIC KEY-----\n"

# --- JWT Authentication Decorator ---
def token_required(f):
    """A decorator to protect endpoints with JWT authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({'message': 'Bearer token malformed'}), 401
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            users = load_json_file(USERS_FILE)
            current_user = next((u for u in users if u['user_id'] == data['user_id']), None)
            if not current_user:
                return jsonify({'message': 'User not found!'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
            
        return f(current_user, *args, **kwargs)
    return decorated

# --- User Management & Authentication Endpoints ---
@app.route("/register", methods=["POST"])
def register_user():
    data = request.get_json()
    if not all(k in data for k in ['username', 'password', 'public_key']):
        return jsonify({"error": "Username, password, and public_key are required"}), 400
        
    users = load_json_file(USERS_FILE)
    if any(u['username'] == data['username'] for u in users):
        return jsonify({"error": "Username already exists"}), 409
        
    new_user = {
        "user_id": f"user_{uuid.uuid4().hex[:8]}",
        "username": data['username'],
        "password_hash": generate_password_hash(data['password']),
        "public_key_pem": data['public_key']
    }
    users.append(new_user)
    save_json_file(users, USERS_FILE)
    
    return jsonify({"message": "User registered successfully", "user_id": new_user['user_id']}), 201

@app.route("/login", methods=["POST"])
def login_user():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return jsonify({'message': 'Could not verify'}), 401, {'WWW-Authenticate': 'Basic realm="Login required!"'}
        
    users = load_json_file(USERS_FILE)
    user = next((u for u in users if u['username'] == auth.username), None)
    
    if not user or not check_password_hash(user['password_hash'], auth.password):
        return jsonify({'message': 'Could not verify'}), 401, {'WWW-Authenticate': 'Basic realm="Login required!"'}
        
    token = jwt.encode({
        'user_id': user['user_id'],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, app.config['SECRET_KEY'], "HS256")
    
    return jsonify({'token': token})

# --- Layer 1 & 2 Endpoints ---
@app.route("/mask/static", methods=["POST"])
@token_required
def handle_static_mask(current_user):
    masked_data = mask_data_recursively(request.get_json())
    fname = f"masked_data_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.json"
    paths = []
    for d in ['./dev', './test']:
        os.makedirs(d, exist_ok=True); fpath = os.path.join(d, fname)
        with open(fpath, 'w') as f: json.dump(masked_data, f, indent=2)
        paths.append(fpath)
    return jsonify({"message": "Masked data saved", "saved_filepaths": paths})

@app.route("/mask/dynamic", methods=["POST"])
@token_required
def handle_dynamic_mask(current_user):
    role = request.args.get('role')
    if not role: return jsonify({"error": "'role' parameter is required."}), 400
    data = request.get_json()
    rules = {r['field']: r['masking_type'] for r in load_json_file(RULES_FILE) if r['role'] == role}
    masked = data.copy()
    for k, v in masked.items():
        if k in rules and MASKING_FUNCTIONS.get(rules[k]):
            masked[k] = MASKING_FUNCTIONS[rules[k]](v)
    return jsonify(masked)
    
@app.route("/rules", methods=["GET", "POST"])
def handle_rules():
    if request.headers.get('X-Admin-API-Key') != ADMIN_API_KEY:
        return jsonify({"error": "Unauthorized: Admin API key required"}), 401
    
    if request.method == "GET":
        return jsonify(load_json_file(RULES_FILE))
    
    if request.method == "POST":
        rule = request.get_json()
        if not all(k in rule for k in ['role', 'field', 'masking_type']): return jsonify({"error": "Invalid rule format"}), 400
        rules = load_json_file(RULES_FILE)
        rule['rule_id'] = f"rule_{uuid.uuid4().hex[:6]}"; rules.append(rule)
        save_json_file(rules, RULES_FILE)
        return jsonify(rule), 201

# --- Layer 4: DUAL-KEY ENCRYPTION (KEY SPLITTING) FOR JSON ---
@app.route("/encrypt", methods=["POST"])
@token_required
def handle_encrypt_dual_key(current_user):
    data = request.get_json()
    client_pk_pem = current_user['public_key_pem']
    aes_key = get_random_bytes(32)
    key_half_a, key_half_b = aes_key[:16], aes_key[16:]
    cipher_aes = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(json.dumps(data).encode('utf-8'))
    try:
        sanitized_pem = sanitize_pem_key(client_pk_pem)
        client_pk = RSA.import_key(sanitized_pem)
        cipher_rsa_client = PKCS1_OAEP.new(client_pk)
        encrypted_half_a = cipher_rsa_client.encrypt(key_half_a)
        with open('server_public.pem', 'rb') as f: server_pk = RSA.import_key(f.read())
        cipher_rsa_server = PKCS1_OAEP.new(server_pk)
        encrypted_half_b = cipher_rsa_server.encrypt(key_half_b)
    except (ValueError, TypeError) as e:
        return jsonify({"error": "Key wrapping failed", "details": str(e)}), 400
    record = { "user_id": current_user['user_id'], "payload": {"ct_b64": base64.b64encode(ciphertext).decode('utf-8'), "n_b64": base64.b64encode(cipher_aes.nonce).decode('utf-8'), "t_b64": base64.b64encode(tag).decode('utf-8')}, "key_halves": {"client_encrypted_b64": base64.b64encode(encrypted_half_a).decode('utf-8'), "server_encrypted_b64": base64.b64encode(encrypted_half_b).decode('utf-8')}}
    db = load_json_file(DATA_FILE)
    db.append(record); save_json_file(db, DATA_FILE)
    return jsonify({"message": "Data encrypted successfully", "user_id": current_user['user_id']})

@app.route("/decrypt", methods=["GET"])
@token_required
def handle_decrypt_dual_key(current_user):
    user_id_to_decrypt = request.args.get('user_id')
    if current_user['user_id'] != user_id_to_decrypt: return jsonify({'message': 'Forbidden'}), 403
    try:
        db = load_json_file(DATA_FILE)
        record = next((i for i in reversed(db) if i["user_id"] == user_id_to_decrypt), None)
        if not record: return jsonify({"error": "Data not found"}), 404
        server_encrypted_half = base64.b64decode(record['key_halves']['server_encrypted_b64'])
        with open('server_private.pem', 'rb') as f: server_sk = RSA.import_key(f.read())
        cipher_rsa_server = PKCS1_OAEP.new(server_sk)
        decrypted_half_b = cipher_rsa_server.decrypt(server_encrypted_half)
        return jsonify({"user_id": user_id_to_decrypt, "payload": record['payload'], "client_encrypted_half_a_b64": record['key_halves']['client_encrypted_b64'], "decrypted_half_b_b64": base64.b64encode(decrypted_half_b).decode('utf-8')})
    except: return jsonify({"error": "Server-side decryption failed"}), 500

# --- Layer 4: DUAL-KEY ENCRYPTION (KEY SPLITTING) FOR FILES ---
@app.route("/encrypt-file", methods=["POST"])
@token_required
def handle_encrypt_file_dual_key(current_user):
    file = request.files.get('file')
    if not file: return jsonify({"error": "File part is required"}), 400
    client_pk_pem = current_user['public_key_pem']
    aes_key = get_random_bytes(32)
    key_half_a, key_half_b = aes_key[:16], aes_key[16:]
    cipher_aes = AES.new(aes_key, AES.MODE_GCM)
    os.makedirs(ENCRYPTED_FILES_DIR, exist_ok=True)
    enc_path = os.path.join(ENCRYPTED_FILES_DIR, f"{current_user['user_id']}_{file.filename}.enc")
    with open(enc_path, 'wb') as ef:
        ef.write(cipher_aes.nonce)
        while chunk := file.stream.read(4096): ef.write(cipher_aes.encrypt(chunk))
    tag = cipher_aes.digest()
    try:
        sanitized_pem = sanitize_pem_key(client_pk_pem)
        client_pk = RSA.import_key(sanitized_pem)
        cipher_rsa_client = PKCS1_OAEP.new(client_pk)
        encrypted_half_a = cipher_rsa_client.encrypt(key_half_a)
        with open('server_public.pem', 'rb') as f: server_pk = RSA.import_key(f.read())
        cipher_rsa_server = PKCS1_OAEP.new(server_pk)
        encrypted_half_b = cipher_rsa_server.encrypt(key_half_b)
    except (ValueError, TypeError) as e: return jsonify({"error": "File key wrapping failed", "details": str(e)}), 400
    meta_path = enc_path + ".meta"
    with open(meta_path, 'w') as mf: json.dump({'t_b64': base64.b64encode(tag).decode('utf-8'), 'key_halves': {'client_encrypted_b64': base64.b64encode(encrypted_half_a).decode('utf-8'), 'server_encrypted_b64': base64.b64encode(encrypted_half_b).decode('utf-8')}}, mf)
    return jsonify({"message": "File encrypted successfully", "stored_path": enc_path})

@app.route("/decrypt-file-prepare", methods=["GET"])
@token_required
def handle_decrypt_file_prepare(current_user):
    filename = request.args.get('filename')
    if not filename: return jsonify({"error": "filename parameter is required."}), 400
    user_id = current_user['user_id']
    try:
        meta_path = os.path.join(ENCRYPTED_FILES_DIR, f"{user_id}_{filename}.enc.meta")
        with open(meta_path, 'r') as f: metadata = json.load(f)
        server_encrypted_half = base64.b64decode(metadata['key_halves']['server_encrypted_b64'])
        with open('server_private.pem', 'rb') as f: server_sk = RSA.import_key(f.read())
        cipher_rsa_server = PKCS1_OAEP.new(server_sk)
        decrypted_half_b = cipher_rsa_server.decrypt(server_encrypted_half)
        enc_path = os.path.join(ENCRYPTED_FILES_DIR, f"{user_id}_{filename}.enc")
        with open(enc_path, 'rb') as f: nonce = f.read(16)
        return jsonify({"message": "Ready for client-side decryption", "nonce_b64": base64.b64encode(nonce).decode('utf-8'), "tag_b64": metadata['t_b64'], "client_encrypted_half_a_b64": metadata['key_halves']['client_encrypted_b64'], "decrypted_half_b_b64": base64.b64encode(decrypted_half_b).decode('utf-8')})
    except: return jsonify({"error": "Server-side file decryption preparation failed"}), 500

@app.route("/download-file", methods=["GET"])
@token_required
def handle_download_file(current_user):
    filename = request.args.get('filename')
    if not filename: return jsonify({"error": "filename parameter is required."}), 400
    user_id = current_user['user_id']
    file_path = os.path.join(ENCRYPTED_FILES_DIR, f"{user_id}_{filename}.enc")
    if not os.path.exists(file_path): return jsonify({"error": "File not found"}), 404
    def generate_chunks():
        with open(file_path, "rb") as f:
            f.read(16) # Skip the nonce
            while chunk := f.read(4096):
                yield chunk
    mimetype, _ = mimetypes.guess_type(filename)
    return app.response_class(generate_chunks(), mimetype=mimetype or 'application/octet-stream')

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)


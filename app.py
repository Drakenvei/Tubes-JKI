from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_socketio import SocketIO, emit, join_room, leave_room
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from werkzeug.security import generate_password_hash, check_password_hash
import base64
import secrets
import json
import sqlite3
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
socketio = SocketIO(app, cors_allowed_origins="*")

# Database setup
DATABASE = 'chat_app.db'

def init_db():
    """Initialize the database with required tables"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            public_key TEXT,
            private_key TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Chat messages table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            room TEXT NOT NULL,
            message TEXT NOT NULL,
            is_private BOOLEAN DEFAULT FALSE,
            target_user_id INTEGER,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sender_id) REFERENCES users (id),
            FOREIGN KEY (target_user_id) REFERENCES users (id)
        )
    ''')
    
    # Rooms table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS rooms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # User sessions table (for tracking online users)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_id TEXT UNIQUE NOT NULL,
            room TEXT,
            is_active BOOLEAN DEFAULT TRUE,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # This enables column access by name
    return conn

# Storage untuk user online
online_users = {}  # {session_id: {'user_id': int, 'username': str, 'room': str}}
rooms = {}  # {room_id: [session_ids]}

def generate_key_pair():
    """Generate RSA key pair"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    public_key = private_key.public_key()
    
    # Serialize keys
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem.decode('utf-8'), public_pem.decode('utf-8')

def encrypt_message(message, public_key_pem):
    """Encrypt message using RSA public key"""
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
        encrypted = public_key.encrypt(
            message.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted).decode('utf-8')
    except Exception as e:
        print(f"Encryption error: {e}")
        return None

def decrypt_message(encrypted_message, private_key_pem):
    """Decrypt message using RSA private key"""
    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None
        )
        encrypted_bytes = base64.b64decode(encrypted_message.encode('utf-8'))
        decrypted = private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode('utf-8')
    except Exception as e:
        print(f"Decryption error: {e}")
        return None

def save_message_to_db(sender_id, room, message, is_private=False, target_user_id=None):
    """Save message to database"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO messages (sender_id, room, message, is_private, target_user_id)
        VALUES (?, ?, ?, ?, ?)
    ''', (sender_id, room, message, is_private, target_user_id))
    
    conn.commit()
    conn.close()

def get_chat_history(room, user_id, limit=50):
    """Get chat history for a room"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get public messages and private messages for this user
    cursor.execute('''
        SELECT m.*, u.username as sender_username, tu.username as target_username
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        LEFT JOIN users tu ON m.target_user_id = tu.id
        WHERE m.room = ? AND (
            m.is_private = FALSE OR 
            m.sender_id = ? OR 
            m.target_user_id = ?
        )
        ORDER BY m.timestamp DESC
        LIMIT ?
    ''', (room, user_id, user_id, limit))
    
    messages = cursor.fetchall()
    conn.close()
    
    # Convert to list of dicts and reverse to get chronological order
    result = []
    for msg in reversed(messages):
        result.append({
            'id': msg['id'],
            'sender_id': msg['sender_id'],
            'sender': msg['sender_username'],
            'message': msg['message'],
            'is_private': bool(msg['is_private']),
            'target_user_id': msg['target_user_id'],
            'target_username': msg['target_username'],
            'timestamp': msg['timestamp']
        })
    
    return result

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('chat.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'success': False, 'message': 'Username dan password harus diisi'})
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return jsonify({
                'success': True, 
                'message': 'Login berhasil',
                'user': {
                    'id': user['id'],
                    'username': user['username'],
                    'public_key': user['public_key'],
                    'private_key': user['private_key']
                }
            })
        else:
            return jsonify({'success': False, 'message': 'Username atau password salah'})
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        
        if not username or not email or not password:
            return jsonify({'success': False, 'message': 'Semua field harus diisi'})
        
        # Generate key pair for new user
        private_key, public_key = generate_key_pair()
        
        conn = get_db_connection()
        
        # Check if username or email already exists
        existing_user = conn.execute('SELECT * FROM users WHERE username = ? OR email = ?', 
                                   (username, email)).fetchone()
        
        if existing_user:
            conn.close()
            return jsonify({'success': False, 'message': 'Username atau email sudah digunakan'})
        
        # Create new user
        password_hash = generate_password_hash(password)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, public_key, private_key)
            VALUES (?, ?, ?, ?, ?)
        ''', (username, email, password_hash, public_key, private_key))
        
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True, 
            'message': 'Registrasi berhasil',
            'user': {
                'id': user_id,
                'username': username,
                'public_key': public_key,
                'private_key': private_key
            }
        })
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/generate-keys', methods=['POST'])
def generate_keys():
    """Generate new RSA key pair for user"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    private_key, public_key = generate_key_pair()
    
    # Update keys in database
    conn = get_db_connection()
    conn.execute('UPDATE users SET public_key = ?, private_key = ? WHERE id = ?',
                (public_key, private_key, session['user_id']))
    conn.commit()
    conn.close()
    
    return jsonify({
        'private_key': private_key,
        'public_key': public_key
    })

@app.route('/chat-history/<room>')
def chat_history(room):
    """Get chat history for a room"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    history = get_chat_history(room, session['user_id'])
    return jsonify({'messages': history})

@socketio.on('connect')
def on_connect():
    print(f'User connected: {request.sid}')
    if 'user_id' in session:
        # Update user session in database
        conn = get_db_connection()
        conn.execute('''
            INSERT OR REPLACE INTO user_sessions (user_id, session_id, is_active, last_seen)
            VALUES (?, ?, TRUE, CURRENT_TIMESTAMP)
        ''', (session['user_id'], request.sid))
        conn.commit()
        conn.close()

@socketio.on('disconnect')
def on_disconnect():
    session_id = request.sid
    if session_id in online_users:
        user_data = online_users[session_id]
        username = user_data['username']
        room = user_data.get('room')
        
        # Remove from room
        if room and room in rooms:
            if session_id in rooms[room]:
                rooms[room].remove(session_id)
            if not rooms[room]:
                del rooms[room]
        
        # Remove from online users
        del online_users[session_id]
        
        # Update database
        conn = get_db_connection()
        conn.execute('UPDATE user_sessions SET is_active = FALSE WHERE session_id = ?', (session_id,))
        conn.commit()
        conn.close()
        
        # Notify room
        if room:
            emit('user_left', {
                'username': username,
                'timestamp': datetime.now().strftime('%H:%M:%S')
            }, room=room)
            
            # Update user list
            room_users = []
            for sid in rooms.get(room, []):
                if sid in online_users:
                    user_data = online_users[sid]
                    conn = get_db_connection()
                    user = conn.execute('SELECT public_key FROM users WHERE id = ?', (user_data['user_id'],)).fetchone()
                    conn.close()
                    room_users.append({
                        'id': sid,
                        'username': user_data['username'],
                        'public_key': user['public_key'] if user else ''
                    })
            emit('update_users', {'users': room_users}, room=room)
    
    print(f'User disconnected: {request.sid}')

@socketio.on('join_chat')
def on_join_chat(data):
    if 'user_id' not in session:
        emit('error', {'message': 'Not logged in'})
        return
    
    session_id = request.sid
    user_id = session['user_id']
    username = session['username']
    room = data.get('room', 'general')
    
    # Get user's public key from database
    conn = get_db_connection()
    user = conn.execute('SELECT public_key FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    
    if not user:
        emit('error', {'message': 'User not found'})
        return
    
    public_key = user['public_key']
    
    # Store online user info
    online_users[session_id] = {
        'user_id': user_id,
        'username': username,
        'room': room
    }
    
    # Join room
    join_room(room)
    if room not in rooms:
        rooms[room] = []
    if session_id not in rooms[room]:
        rooms[room].append(session_id)
    
    # Update database
    conn = get_db_connection()
    conn.execute('UPDATE user_sessions SET room = ? WHERE session_id = ?', (room, session_id))
    conn.commit()
    conn.close()
    
    # Notify room
    emit('user_joined', {
        'username': username,
        'timestamp': datetime.now().strftime('%H:%M:%S')
    }, room=room)
    
    # Send updated user list with public keys
    room_users = []
    for sid in rooms[room]:
        if sid in online_users:
            user_data = online_users[sid]
            conn = get_db_connection()
            user = conn.execute('SELECT public_key FROM users WHERE id = ?', (user_data['user_id'],)).fetchone()
            conn.close()
            room_users.append({
                'id': sid,
                'username': user_data['username'],
                'public_key': user['public_key'] if user else ''
            })
    
    emit('update_users', {'users': room_users}, room=room)
    
    # Send chat history
    history = get_chat_history(room, user_id)
    emit('chat_history', {'messages': history})
    
    # Confirm join
    emit('join_confirmed', {
        'room': room,
        'your_id': session_id
    })

@socketio.on('send_message')
def on_send_message(data):
    if 'user_id' not in session:
        emit('error', {'message': 'Not logged in'})
        return
    
    session_id = request.sid
    if session_id not in online_users:
        return
    
    user_data = online_users[session_id]
    user_id = user_data['user_id']
    username = user_data['username']
    room = user_data['room']
    original_message = data.get('original_message') # Kita akan selalu menggunakan original_message dari client
    target_session_id = data.get('target_user_id') # Ini adalah session_id dari target

    timestamp = datetime.now().strftime('%H:%M:%S')

    # Jika ini adalah pesan pribadi (private message)
    if target_session_id:
        # 1. Pastikan target online
        if target_session_id not in online_users:
            emit('error', {'message': 'User is offline or does not exist.'}, room=session_id)
            return
            
        target_info = online_users[target_session_id]
        target_db_id = target_info['user_id']
        
        # Simpan pesan plaintext ke database
        save_message_to_db(user_id, room, original_message, is_private=True, target_user_id=target_db_id)

        # 2. Ambil kunci publik target dari database
        conn = get_db_connection()
        target_user_db = conn.execute('SELECT public_key FROM users WHERE id = ?', (target_db_id,)).fetchone()
        conn.close()

        if not target_user_db or not target_user_db['public_key']:
            emit('error', {'message': 'Target user does not have a public key.'}, room=session_id)
            return

        # 3. Enkripsi pesan menggunakan kunci publik target
        encrypted_message = encrypt_message(original_message, target_user_db['public_key'])
        
        if not encrypted_message:
            emit('error', {'message': 'Failed to encrypt message.'}, room=session_id)
            return

        # 4. Kirim pesan plaintext kembali ke PENGIRIM
        emit('receive_message', {
            'sender_id': session_id,
            'sender': username,
            'message': original_message, # Kirim plaintext ke diri sendiri
            'timestamp': timestamp,
            'target_user_id': target_session_id,
            'is_private': True,
            'is_sender': True
        }, room=session_id)
        
        # 5. Kirim pesan terenkripsi ke PENERIMA
        emit('receive_message', {
            'sender_id': session_id,
            'sender': username,
            'message': encrypted_message, # Kirim hasil enkripsi ke target
            'timestamp': timestamp,
            'target_user_id': target_session_id,
            'is_private': True,
            'is_sender': False
        }, room=target_session_id)

    else:
        # Pesan publik (tidak ada enkripsi)
        save_message_to_db(user_id, room, original_message, is_private=False, target_user_id=None)
        
        emit('receive_message', {
            'sender_id': session_id,
            'sender': username,
            'message': original_message,
            'timestamp': timestamp,
            'target_user_id': None,
            'is_private': False
        }, room=room)
        
@socketio.on('typing')
def on_typing(data):
    session_id = request.sid
    if session_id not in online_users:
        return
    
    user_data = online_users[session_id]
    username = user_data['username']
    room = user_data['room']
    
    emit('user_typing', {
        'username': username,
        'is_typing': data['is_typing']
    }, room=room, include_self=False)

if __name__ == '__main__':
    # Initialize database
    init_db()
    
    # Ensure default room exists
    conn = get_db_connection()
    conn.execute('INSERT OR IGNORE INTO rooms (name) VALUES (?)', ('general',))
    conn.commit()
    conn.close()
    
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
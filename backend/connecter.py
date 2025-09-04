from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from Bcrypt import Bcrypt  

app = Flask(__name__, static_folder='../frontend')
CORS(app)
bcrypt = Bcrypt()

@app.route('/')
def serve_index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:filename>')
def serve_static_files(filename):
    return send_from_directory(app.static_folder, filename)

@app.route('/hash', methods=['POST'])
def hash_password():
    data = request.get_json()
    password = data.get('password')
    salt_len = data.get('salt_len')
    cost = data.get('cost')

    if not password or salt_len is None or cost is None:
        return jsonify({'error': 'Password, salt_len, and cost are required'}), 400

    try:
        hashed = bcrypt.hash_password(password, salt_len, cost)
        return jsonify({'hash': hashed})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/verify', methods=['POST'])
def verify_password():
    data = request.get_json()
    password = data.get('password')
    hashed = data.get('hash')

    if not password or not hashed:
        return jsonify({'error': 'Password and hash are required'}), 400

    try:
        result = bcrypt.verify(password, hashed)
        return jsonify({'match': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
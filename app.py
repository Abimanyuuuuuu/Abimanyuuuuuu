from flask import Flask, request, jsonify, render_template
import base64
import zlib
import urllib.parse
from xml.etree import ElementTree as ET

app = Flask(__name__)

def decode_base64(encoded_str):
    try:
        decoded_bytes = base64.b64decode(encoded_str)
        decoded_str = decoded_bytes.decode('utf-8')
        return decoded_str
    except Exception as e:
        return f"Base64 decoding error: {e}"

def decode_base64url(encoded_str):
    try:
        encoded_str = encoded_str.replace('-', '+').replace('_', '/')
        padding = len(encoded_str) % 4
        if padding:
            encoded_str += '=' * (4 - padding)
        decoded_bytes = base64.b64decode(encoded_str)
        decoded_str = decoded_bytes.decode('utf-8')
        return decoded_str
    except Exception as e:
        return f"Base64 URL decoding error: {e}"

def decode_url(encoded_str):
    try:
        decoded_str = urllib.parse.unquote(encoded_str)
        return decoded_str
    except Exception as e:
        return f"URL decoding error: {e}"

def decode_saml(saml_input):
    try:
        decoded_bytes = base64.b64decode(saml_input)
        try:
            decoded_bytes = zlib.decompress(decoded_bytes, -15)
        except zlib.error:
            pass
        decoded_string = decoded_bytes.decode('utf-8')
        try:
            root = ET.fromstring(decoded_string)
            decoded_string = ET.tostring(root, encoding='unicode', method='xml')
        except ET.ParseError:
            pass
        return decoded_string
    except Exception as e:
        return f"SAML decoding error: {e}"

def decode_hex(hex_string):
    try:
        byte_data = bytes.fromhex(hex_string)
        decoded_string = byte_data.decode('utf-8')
        return decoded_string
    except ValueError as e:
        return f"Hexadecimal input error: {e}"
    except UnicodeDecodeError as e:
        return f"Hexadecimal decoding error: {e}"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/decode', methods=['POST'])
def decode():
    data = request.json
    encoded_string = data.get('encodedString', '')

    return jsonify({
        'base64': decode_base64(encoded_string),
        'base64url': decode_base64url(encoded_string),
        'url': decode_url(encoded_string),
        'saml': decode_saml(encoded_string),
        'hex': decode_hex(encoded_string)
    })

if __name__ == "__main__":
    app.run(debug=True)

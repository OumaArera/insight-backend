from email.utils import formataddr
from flask import Flask, request, jsonify, make_response
from flask_restful import Api
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token, get_jwt, unset_jwt_cookies
from models import db, User
from datetime import datetime, timezone, timedelta
from flask_cors import CORS
from dotenv import load_dotenv
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES 
from Crypto.Util.Padding import unpad
import base64
import json
import os
import re

load_dotenv()

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("SQLALCHEMY_DATABASE_URI")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)
app.config["ENCRYPTION_KEY"] = os.getenv("EN_SECRET_KEY")

app.config['SMTP_SERVER_ADDRESS'] = os.getenv("SMTP_SERVER_ADDRESS")
app.config['SMTP_USERNAME'] = os.getenv("SMTP_USERNAME")
app.config['SMTP_PASSWORD'] = os.getenv("SMTP_PASSWORD")
app.config['SMTP_PORT'] = os.getenv("SMTP_PORT")
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'Images')

db.init_app(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
api = Api(app)
CORS(app)

@app.route('/')
def index():
    return '<h1>Insight wellbeing App</h1>'

ENCRYPTION_KEY = app.config["ENCRYPTION_KEY"]
print(ENCRYPTION_KEY)

def decrypt_message(ciphertext, iv):
    try:
        # Decode the base64 encoded string
        ciphertext = base64.b64decode(ciphertext)
        iv = bytes.fromhex(iv)
        cipher = AES.new(ENCRYPTION_KEY.encode("utf-8"), AES.MODE_CBC, iv)
        # Decrypt the message
        decrypted_message = cipher.decrypt(ciphertext)
        # Unpad the decrypted message
        decrypted_message = unpad(decrypted_message, AES.block_size)
        decrypted_message_utf8 = decrypted_message.decode("utf-8")
        return decrypted_message_utf8
    except UnicodeDecodeError as e:
        print("Decryption Error:", e)
        return f"Decryption Error: {str(e)}"
    except ValueError as e:
        print("Padding Error:", e)
        return f"Padding Error: {str(e)}"
    except Exception as e:
        print("General Error:", e)
        return f"General Error: {str(e)}"


@app.route('/users/signup', methods=['POST'])
def signup():
    data = request.get_json()
    ciphertext = data.get('ciphertext')
    iv = data.get('iv')

    try:
        decrypted_data = decrypt_message(ciphertext, iv)

        # Print decrypted data for verification
        print("Decrypted User Data:", decrypted_data)

        # Attempt to load decrypted data as JSON
        user_data = json.loads(decrypted_data)

        # Validate required fields
        if not all(key in user_data for key in ('firstName', 'lastName', 'email', 'password')):
            return jsonify({"message": "Incomplete user data received", "status_code": 400, "successful": False}), 400

        # Check if the user with the provided email already exists
        existing_user = User.query.filter_by(email=user_data['email']).first()
        if existing_user:
            return jsonify({'message': 'User with this email already exists', 'status_code': 400, 'successful': False}), 400

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(user_data['password']).decode("utf-8")

        new_user = User(
            first_name=user_data['firstName'],
            last_name=user_data['lastName'],
            email=user_data['email'],
            password=hashed_password,
            created_at=datetime.now(timezone.utc),
            last_login=datetime.now(timezone.utc)
        )

        # Persist the new user to the database
        db.session.add(new_user)
        db.session.commit()

        # Return success response
        return jsonify({'message': f'User created successfully: {decrypted_data} {hashed_password}', 'status_code': 201, 'successful': True}), 201

    except json.JSONDecodeError as json_error:
        return jsonify({'message': f"JSON decoding error: {str(json_error)}", 'status_code': 400, 'successful': False}), 400

    except Exception as e:
        return jsonify({'message': f"Error: {str(e)}", 'status_code': 400, 'successful': False}), 400

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5555, debug=True)

from email.utils import formataddr
from flask import Flask, request, jsonify, make_response
from flask_restful import Api
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token, get_jwt, unset_jwt_cookies
from models import db, User, PatientHistory
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

        # Attempt to load decrypted data as JSON
        user_data = json.loads(decrypted_data)

        # Validate required fields
        if not all(key in user_data for key in ('firstName', 'lastName', 'email', 'password', "role")):
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
            role=user_data["role"],
            password=hashed_password,
            created_at=datetime.now(timezone.utc),
            last_login=datetime.now(timezone.utc)
        )

        # Persist the new user to the database
        db.session.add(new_user)
        db.session.commit()

        # Return success response
        return jsonify({'message': f'User created successfully', 'status_code': 201, 'successful': True}), 201

    except json.JSONDecodeError as json_error:
        return jsonify({'message': f"JSON decoding error: {str(json_error)}", 'status_code': 400, 'successful': False}), 400

    except Exception as e:
        return jsonify({'message': f"Error: {str(e)}", 'status_code': 400, 'successful': False}), 400
    

@app.route("/users/login", methods=["POST"])
def login():
    data = request.get_json()
    ciphertext = data.get('ciphertext')
    iv = data.get('iv')

    if not data:
        return jsonify({"message": "Empty data", "successful": False, "status_code": 400}), 400

    try:
        decrypted_data = decrypt_message(ciphertext, iv)

        # Attempt to load decrypted data as JSON
        login_data = json.loads(decrypted_data)
        email = login_data.get("email").lower() if data.get('email') else None

        # Validate required fields
        if not all(key in login_data for key in ('email', 'password')):
            return jsonify({"message": "Incomplete login data received", "status_code": 400, "successful": False}), 400

        # Retrieve the user from the database using the provided email
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'message': 'Invalid email or password', 'status_code': 401, 'successful': False}), 401

        if user.status != "active":
            return jsonify({'message': 'Access denied! Please contact system administrator.', 'status_code': 403, 'successful': False}), 403
        # Verify the password
        if not bcrypt.check_password_hash(user.password, login_data['password']):
            return jsonify({'message': 'Invalid email or password', 'status_code': 401, 'successful': False}), 401

        access_token = create_access_token(identity=user.id)

        # Prepare user data for encryption
        user_data = {
            "firstName": user.first_name,
            "lastName": user.last_name,
            "role": user.role,
            "id": user.id,
            "email": user.email,
            "lastLogin": user.last_login.isoformat(),
            "accessToken": access_token  # Include the access token
        }

        user_data_json = json.dumps(user_data)
        new_iv = os.urandom(16)
        cipher = AES.new(ENCRYPTION_KEY.encode("utf-8"), AES.MODE_CBC, new_iv)
        padded_user_data = user_data_json + (AES.block_size - len(user_data_json) % AES.block_size) * "\0"
        encrypted_user_data = cipher.encrypt(padded_user_data.encode("utf-8"))

        encrypted_user_data_b64 = base64.b64encode(encrypted_user_data).decode("utf-8")
        iv_b64 = new_iv.hex()

        return jsonify({"ciphertext": encrypted_user_data_b64, "iv": iv_b64, "message": "Login successful", "status_code": 201, "successful": True}), 201

    except json.JSONDecodeError as json_error:
        return jsonify({'message': f"JSON decoding error: {str(json_error)}", 'status_code': 400, 'successful': False}), 400

    except Exception as e:
        return jsonify({'message': f"Error: {str(e)}", 'status_code': 400, 'successful': False}), 400


@app.route("/users/patient-history", methods=["POST"])
@jwt_required()
def post_patient_history():
    data = request.get_json()
    ciphertext = data.get('ciphertext')
    iv = data.get('iv')

    try:
        decrypted_data = decrypt_message(ciphertext, iv)

        user_data = json.loads(decrypted_data)

        if not all(key in user_data for key in ('userId', 'pageNo', 'questions', 'date')):
            return jsonify({"message": "Incomplete user data received", "status_code": 400, "successful": False}), 400

        page_no = user_data.get("pageNo")
        user_id = user_data.get("userId")
        questions = user_data.get("questions")
        date = user_data.get("date")

        try:
            page_no = int(page_no)
            user_id = int(user_id)
            date = datetime.strptime(date, "%Y-%m-%dT%H:%M:%S.%fZ")

        except ValueError as err:
            return jsonify({"message": f"Page number must be a number, and date must be of the right format: {err}", "status_code": 400, "successful": False}), 400

        existing_history = PatientHistory.query.filter_by(page_no=page_no, user_id=user_id).first()

        if existing_history:
            return jsonify({"message": "You already provided this data", "status_code": 400, "successful": False}), 400

        user = User.query.filter_by(id=user_id).first()

        if not user:
            return jsonify({"message": "Invalid user details!", "status_code": 400, "successful": False}), 400
        
        if user.role != "patient" or user.status != "active":
            return jsonify({"message": "You don't have rights to perform this action", "status_code": 400, "successful": False}), 400

        new_history = PatientHistory(
            user_id=user_id,
            page_no=page_no,
            date=date,
            questions=questions
        )

        db.session.add(new_history)
        db.session.commit()

        return jsonify({"message": "Data saved successfully.", "status_code": 201, "successful": True}), 201

    except Exception as err:
        db.session.rollback()
        return jsonify({"message": f"Failed to save the data: Error: {err}", "status_code": 500, "successful": False}), 500


@app.route("/users/delete/<int:id>", methods=["DELETE"])
def delete_user(id):
    user = User.query.filter_by(id=id).first()

    if not user:
        return jsonify({"message": "User does not exist", "successful": False, "status_code": 404}), 404
    
    try:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": f"User {user.first_name} {user.last_name} has been deleted", "successful": True, "status_code": 204}), 201
    except Exception as err:
        db.session.rollback()
        return jsonify({"message": f"Failed to delete {user.first_name} {user.last_name}: Error: {err}", "successful": False, "status_code": 500}), 500 
    



if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5555, debug=True)

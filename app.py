from email.utils import formataddr
from flask import Flask, request, jsonify, make_response
from flask_restful import Api
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token, get_jwt, unset_jwt_cookies
from models import db, User, PatientHistory, Task, Session, Presciption, Impression, HealthResponse, CompletedTask, RatingAndRemarks
from datetime import datetime, timezone, timedelta
from flask_cors import CORS
from dotenv import load_dotenv
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from flask_socketio import SocketIO, emit
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
socketio = SocketIO(app)
CORS(app)

blacklist = set()

@app.route('/')
def index():
    return '<h1>Insight wellbeing App</h1>'

@app.route("/users/logout", methods=["POST"])
@jwt_required()
def logout_user():

    jti = get_jwt()["jti"]
    blacklist.add(jti)

    response = make_response(jsonify({"message": "Logout successful.", "successful": True, "status_code": 201}))

    unset_jwt_cookies(response)

    return response, 201

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
            status=user_data["status"],
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

        # Validate required fields
        if not all(key in login_data for key in ('email', 'password')):
            return jsonify({"message": "Incomplete login data received", "status_code": 400, "successful": False}), 400

        # Retrieve the user from the database using the provided email
        user = User.query.filter_by(email=login_data.get("email")).first()
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
            "accessToken": access_token  
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


@app.route("/users", methods=["GET"])
@jwt_required()
def get_users():
    users = User.query.all()

    if not users:
        return jsonify({"message": "No users yet", "successful": False, "status_code": 404}), 404
    
    users_list = []

    for user in users:
        if user.status == "active":
            users_list.append({
                "userId": user.id,
                "firstName": user.first_name,
                "lastName": user.last_name,
                "role": user.role,
                "email": user.email,
                "registrationDate": user.created_at.isoformat()
            })
    user_data_json = json.dumps(users_list)
    new_iv = os.urandom(16)
    cipher = AES.new(ENCRYPTION_KEY.encode("utf-8"), AES.MODE_CBC, new_iv)
    padded_user_data = user_data_json + (AES.block_size - len(user_data_json) % AES.block_size) * "\0"
    encrypted_user_data = cipher.encrypt(padded_user_data.encode("utf-8"))

    encrypted_user_data_b64 = base64.b64encode(encrypted_user_data).decode("utf-8")
    iv_b64 = new_iv.hex()


    return jsonify({"ciphertext": encrypted_user_data_b64, "iv": iv_b64, "successful": True, "status_code": 200}), 200  


@app.route("/users/patient-history", methods=["POST"])
@jwt_required()
def post_patient_history():
    data = request.get_json()
    ciphertext = data.get('ciphertext')
    iv = data.get('iv')

    try:
        decrypted_data = decrypt_message(ciphertext, iv)

        user_data = json.loads(decrypted_data)

        if not all(key in user_data for key in ('userId', 'pageNo', 'questions', 'date', "approval")):
            return jsonify({"message": "Incomplete user data received", "status_code": 400, "successful": False}), 400

        page_no = user_data.get("pageNo")
        user_id = user_data.get("userId")
        questions = user_data.get("questions")
        date = user_data.get("date")
        approval = user_data.get("approval")

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
            date_time=date,
            questions=questions,
            approval=approval
        )

        db.session.add(new_history)
        db.session.commit()

        return jsonify({"message": "Data saved successfully.", "status_code": 201, "successful": True}), 201

    except Exception as err:
        db.session.rollback()
        return jsonify({"message": f"Failed to save the data: Error: {err}", "status_code": 500, "successful": False}), 500


@app.route("/users/history/<int:user_id>", methods=["GET"])
@jwt_required()
def get_history(user_id):
    history = PatientHistory.query.filter_by(user_id=user_id).all()

    if not history:
        return jsonify({"message": "No data yet", "successful": False, "status_code": 404}), 404

    history_list = []

    for hist in history:
        history_list.append({
            "id": hist.id,
            "user_id": hist.user_id,
            "page_no": hist.page_no,
            "questions": hist.questions,
            "approval": hist.approval,
            "date": hist.date_time.isoformat()
        })

    user_data_json = json.dumps(history_list)
    new_iv = os.urandom(16)
    cipher = AES.new(ENCRYPTION_KEY.encode("utf-8"), AES.MODE_CBC, new_iv)
    padded_user_data = user_data_json + (AES.block_size - len(user_data_json) % AES.block_size) * "\0"
    encrypted_user_data = cipher.encrypt(padded_user_data.encode("utf-8"))

    encrypted_user_data_b64 = base64.b64encode(encrypted_user_data).decode("utf-8")
    iv_b64 = new_iv.hex()


    return jsonify({"ciphertext": encrypted_user_data_b64, "iv": iv_b64, "successful": True, "status_code": 200}), 200


@app.route("/users/task", methods=["POST"])
@jwt_required()
def create_task():
    data = request.get_json()

    if not data:
        return jsonify({"message": "You provided an empty data", "status_code": 400, "successful": False}), 400

    try:
        required_keys = ['activities', "frequency", 'dateTime', 'duration', 'doctorId', 'patientId', 'patientName']
        if not all(key in data for key in required_keys):
            return jsonify({"message": "Incomplete user data received", "status_code": 400, "successful": False}), 400

        try:
            doctor_id = int(data.get("doctorId"))
            patient_id = int(data.get("patientId"))
            date = datetime.strptime(data.get("dateTime"), "%Y-%m-%d %H:%M")
            duration = float(data.get("duration"))
            frequency = int(data.get("frequency"))
            activity = str(data.get("activities"))
            patient_name = str(data.get("patientName"))

            {"activities":"Third Test","dateTime":"2024-07-22 17:27","duration":"2","frequency":"2","doctorId":9,"patientId":8,"patientName":"Ouma Arera"}

        except ValueError as err:
            return jsonify({"message": f"Provide the correct date and time format: {err}", "status_code": 400, "successful": False}), 400

        new_task = Task(
            doctor_id=doctor_id,
            patient_id=patient_id,
            patient_name=patient_name,
            activities=activity,
            date_time=date,
            duration=duration,
            frequency=frequency
        )

        db.session.add(new_task)
        db.session.commit()

        return jsonify({"message": "Task added successfully", "status_code": 201, "successful": True}), 201

    except Exception as err:
        db.session.rollback()
        return jsonify({"message": f"Failed to add the data. Error: {err}", "status_code": 500, "successful": False}), 500


@app.route("/users/tasks/<int:id>", methods=["GET"])
@jwt_required()
def get_tasks(id):
    tasks = Task.query.filter_by(patient_id=id).all()
    reminders = []

    if not tasks:
        return jsonify({"message": "You have no tasks yet", "successful": False, "status_code": 404}), 404

    for task in tasks:
        last_completed_task = CompletedTask.query.filter_by(task_id=task.id).order_by(CompletedTask.completed_time.desc()).first()

        if last_completed_task:
            next_due_time = last_completed_task.completed_time + timedelta(hours=task.duration)
            if next_due_time <= datetime.now():
                # Add to reminders
                reminders.append({
                    "id": task.id,
                    "doctorId": task.doctor_id,
                    "patientId": task.patient_id,
                    "patientName": task.patient_name,
                    "activities": task.activities,
                    "dateTime": task.date_time,
                    "nextDueTime": next_due_time,
                    "duration": task.duration,
                    "frequency": task.frequency
                })
        else:
            # Send a reminder if no last_completed_task exists
            reminders.append({
                "id": task.id,
                "doctorId": task.doctor_id,
                "patientId": task.patient_id,
                "patientName": task.patient_name,
                "activities": task.activities,
                "dateTime": task.date_time,
                "nextDueTime": datetime.now(),
                "duration": task.duration,
                "frequency": task.frequency
            })
    
    # Emit reminders after collecting them
    if reminders:
        socketio.emit('task_reminders', reminders, room=f'patient_{id}')

    return jsonify({"data": reminders, "message": "Data retrieved successfuly",  "successful": True, "status_code": 200}), 200


@app.route("/users/update/task", methods=["POST"])
@jwt_required()
def update_task():
    data = request.get_json()

    if not data:
        return jsonify({"message": "Empty data", "successful": False, "status_code": 400}), 400
    
    task_id = data.get("taskId")
    patient_id = data.get("patientId")
    completed_time = data.get("completedTime")    

    if not task_id or not patient_id or not completed_time:
        return jsonify({"message": "Incomplete data", "successful": False, "status_code": 400}), 400

    patient = User.query.filter_by(id=patient_id).first()

    if not patient:
        return jsonify({"message": "User does not exist", "successful": False, "status_code": 404}), 404
    
    new_task = CompletedTask(
        task_id=task_id,
        patient_id=patient_id,
        completed_time=completed_time
    )
    
    try:
        db.session.add(new_task)
        db.session.commit()
        return jsonify({"message": "Task Completed successfully", "successful": True, "status_code": 201}), 201
    
    except Exception as err:
        db.session.rollback()
        return jsonify({"message": f"There was an error {err}", "successful": False, "status_code": 500}), 500


@app.route("/users/sessions", methods=["POST"])
@jwt_required()
def create_sessions():
    data = request.get_json()

    required_fields = ['physicianId', 'available', "location", "meetingUrl", "meetingLocation", "start_time", "end_time", "session_time"]
    if not all(field in data for field in required_fields):
        return jsonify({"message": "Incomplete data provided", "successful": False, "status_code": 400}), 400

    # date : "2024-08-01 10:00"
    # CreateSessions.jsx:51 meetingType : "online"
    # CreateSessions.jsx:51 location : "url"
    # CreateSessions.jsx:51 userId : 8
    # CreateSessions.jsx:51 approved : false
    
    try:
        physician_id = int(data['physicianId'])
        available = bool(data['available'])
        location = str(data['location'])
        meeting_url = str(data['meetingUrl']) if 'meetingUrl' in data else None
        meeting_location = str(data['meetingLocation']) if 'meetingLocation' in data else None
        start_time = datetime.strptime(data['start_time'], "%Y-%m-%d %H:%M")
        end_time = datetime.strptime(data['end_time'], "%Y-%m-%d %H:%M")
        session_time = datetime.strptime(data['session_time'], "%Y-%m-%d %H:%M")
        patient_id = int(data['patient_id']) if 'patient_id' in data else None

        # Check for overlapping sessions for the same physician
        overlapping_session = Session.query.filter(
            Session.physician_id == physician_id,
            Session.start_time < end_time,
            Session.end_time > start_time
        ).first()

        if overlapping_session:
            return jsonify({"message": "There is already another session at the specified time", "successful": False, "status_code": 400}), 400

    except (ValueError, TypeError) as e:
        return jsonify({"message": f"Invalid data type provided: {str(e)}", "successful": False, "status_code": 400}), 400

    new_session = Session(
        physician_id=physician_id,
        available=available,
        location=location,
        meeting_url=meeting_url,
        meeting_location=meeting_location,
        start_time=start_time,
        end_time=end_time,
        session_time=session_time,
        patient_id=patient_id
    )

    try:
        db.session.add(new_session)
        db.session.commit()
        return jsonify({"message": "Session created successfully", "successful": True, "status_code": 201}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": f"Failed to create session: {str(e)}", "successful": False, "status_code": 500}), 500


@app.route("/users/all/sessions", methods=["GET"])
@jwt_required()
def get_all_sessions():
    try:
        # Query for all sessions where available is True
        sessions = Session.query.filter_by(available=True).all()

        if not sessions:
            return jsonify({"message": "No sessions available", "successful": False, "status_code": 404}), 404

        # Serialize session data
        session_list = []
        for session in sessions:
            session_data = {
                "id": session.id,
                "physicianId": session.physician_id,
                "available": session.available,
                "location": session.location,
                "meetingUrl": session.meeting_url,
                "meetingLocation": session.meeting_location,
                "start_time": session.start_time.strftime("%Y-%m-%d %H:%M:%S"),
                "end_time": session.end_time.strftime("%Y-%m-%d %H:%M:%S"),
                "session_time": session.session_time.strftime("%Y-%m-%d %H:%M:%S"),
                "patient_id": session.patient_id
            }
            session_list.append(session_data)

        return jsonify({"sessions": session_list, "successful": True, "status_code": 200}), 200

    except Exception as e:
        return jsonify({"message": f"Failed to retrieve sessions: {str(e)}", "successful": False, "status_code": 500}), 500


@app.route("/users/book/session/<int:id>", methods=["PUT"])
@jwt_required()
def book_session(id):
    data = request.get_json()
    user_id = data.get("userId")

    if not user_id:
        return jsonify({"message": "You provided incomplete data", "successful": False, "status_code": 400}), 400

    session = Session.query.filter_by(id=id).first()

    if not session:
        return jsonify({"message": "Session does not exist", "successful": False, "status_code": 404}), 404
    
    if not session.available:
        return jsonify({"message": "This session is already booked", "successful": False, "status_code": 400}), 400

    session.available = False
    session.patient_id = user_id

    try:
        db.session.commit()
        return jsonify({"message": "Session booked successfully", "successful": True, "status_code": 200}), 200
    except Exception as err:
        db.session.rollback()
        app.logger.error(f"Error booking session: {err}")
        return jsonify({"message": f"There was an error booking the session. Error: {err}", "successful": False, "status_code": 500}), 500


@app.route("/users/get/booking/<int:id>", methods=["GET"])
@jwt_required()
def get_patient_booking(id):
    current_time = datetime.now()
    
    sessions = Session.query.filter(
        (Session.patient_id == id) | (Session.physician_id == id),
        Session.available == False,
        Session.start_time > current_time 
    ).all()
    
    if not sessions:
        return jsonify({"message": "No upcoming sessions found for the specified id", "successful": False, "status_code": 404}), 404
    
    formatted_sessions = []
    for session in sessions:
        formatted_sessions.append({
            "id": session.id,
            "physician_id": session.physician_id,
            "location": session.location,
            "meeting_url": session.meeting_url,
            "meeting_location": session.meeting_location,
            "start_time": session.start_time.strftime('%Y-%m-%d %H:%M:%S'),
            "end_time": session.end_time.strftime('%Y-%m-%d %H:%M:%S'),
            "session_time": session.session_time.strftime('%Y-%m-%d %H:%M:%S'),
            "patient_id": session.patient_id
        })
    
    return jsonify({"sessions": formatted_sessions, "message": "Upcoming sessions retrieved successfully", "successful": True, "status_code": 200}), 200


@app.route("/users/all/tasks/<int:id>", methods=["GET"])
@jwt_required()
def get_all_tasks(id):
    tasks = Task.query.filter_by(doctor_id=id).all()

    if not tasks:
        return jsonify({"message": "No tasks yet", "successful": False, "status_code": 404}), 404

    tasks_list = []

    for task in tasks:
        tasks_list.append(
            {
                "id": task.id,
                "doctorId":task.doctor_id,
                "patientId": task.patient_id,
                "patientName":task.patient_name,
                "activities":task.activities,
                "dateTime": task.date_time,
                "duration": task.duration,
                "frequency": task.frequency
            }
        )

    return jsonify({"tasks": tasks_list, "message": "Tasks retrieved successfully", "successful": True, "status_code": 200}), 200


@app.route("/users/pending/sessions/<int:id>", methods=["GET"])
@jwt_required()
def get_pending_sessions(id):
    sessions = Session.query.filter(Session.physician_id==id, Session.available==True).all()

    if not sessions:
        return jsonify({"message": "No pending sessions found for the specified id", "successful": False, "status_code": 404}), 404


    formatted_sessions = []
    for session in sessions:
        formatted_sessions.append({
            "id": session.id,
            "physician_id": session.physician_id,
            "available": session.available,
            "location": session.location,
            "meeting_url": session.meeting_url,
            "meeting_location": session.meeting_location,
            "start_time": session.start_time.strftime('%Y-%m-%d %H:%M:%S'),
            "end_time": session.end_time.strftime('%Y-%m-%d %H:%M:%S'),
            "session_time": session.session_time.strftime('%Y-%m-%d %H:%M:%S'),
            "patient_id": session.patient_id
        })
    
    return jsonify({"sessions": formatted_sessions, "message": "Upcoming sessions retrieved successfully", "successful": True, "status_code": 200}), 200


@app.route("/users/update/session/<int:id>", methods=["PUT"])
@jwt_required()
def update_sessions(id):
    data = request.get_json()
    start_time = data.get("startTime")
    end_time = data.get("endTime")

    if not start_time or not end_time:
        return jsonify({"message": "You provided no data", "successful": False, "status_code": 400}), 400
    
    try:
        start_time = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S')
        end_time = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S')
    except ValueError as e:
        return jsonify({"message": f"Invalid date format: {e}", "successful": False, "status_code": 400}), 400

    session = Session.query.filter_by(id=id).first()

    if not session:
        return jsonify({"message": "No pending sessions found for the specified id", "successful": False, "status_code": 404}), 404

    session.start_time = start_time
    session.session_time = start_time
    session.end_time = end_time

    try:
        db.session.commit()
        return jsonify({"message": "Session saved successfully", "successful": True, "status_code": 200}), 200
    except Exception as err:
        db.session.rollback()
        return jsonify({"message": f"Failed to update session: {err}", "successful": False, "status_code": 500}), 500


@app.route("/users/patient/history", methods=["GET"])
@jwt_required()
def get_patients_history():
    patients = PatientHistory.query.all()

    if not patients:
        return jsonify({"message": "No data available", "successful": False, "status_code": 404}), 404
    
    patients_history_list = []

    for patient in patients:
        patient_data = User.query.filter_by(id=patient.user_id).first()
        patients_history_list.append({
            "id": patient.id,
            "patientId": patient.user_id,
            "pageNo": patient.page_no,
            "approval": patient.approval,
            "history": patient.questions,
            "patientName": f"{patient_data.first_name} {patient_data.last_name}",
            "dateTime": patient.date_time.isoformat()
        })

    # return jsonify({"data": patients_history_list, "message": "Data retrieved successfully", "successful": True, "status_code":200}), 200

    user_data_json = json.dumps(patients_history_list)
    new_iv = os.urandom(16)
    cipher = AES.new(ENCRYPTION_KEY.encode("utf-8"), AES.MODE_CBC, new_iv)
    padded_user_data = user_data_json + (AES.block_size - len(user_data_json) % AES.block_size) * "\0"
    encrypted_user_data = cipher.encrypt(padded_user_data.encode("utf-8"))

    encrypted_user_data_b64 = base64.b64encode(encrypted_user_data).decode("utf-8")
    iv_b64 = new_iv.hex()

    return jsonify({"ciphertext": encrypted_user_data_b64, "iv": iv_b64, "message": "Data retrived successfully", "status_code": 200, "successful": True}), 200


@app.route("/users/prescription", methods=["POST"])
@jwt_required()
def post_prescription():
    data = request.get_json()
    
    if not data:
        return jsonify({"message": "Empty data", "successful": False, "status_code": 400}), 400
    
    ciphertext = data.get('ciphertext')
    iv = data.get('iv')

    try:
        decrypted_data = decrypt_message(ciphertext, iv)

        prescription = json.loads(decrypted_data)

        if not all(key in prescription for key in ('date', 'patientId', 'doctorId', 'prescription')):
            return jsonify({"message": "Incomplete user data received", "status_code": 400, "successful": False}), 400


        try:
            date = datetime.strptime(prescription.get("date"), "%Y-%m-%dT%H:%M:%S.%fZ")
            patient_id = int(prescription.get("patientId"))
            doctor_id = int(prescription.get("doctorId"))
            prescription_details = str(prescription.get("prescription"))

        except ValueError as err:
            return jsonify({"message": f"Provide the right data format. Error: {err}", "successful": False, "status_code": 400}), 400

        doctor = User.query.filter_by(id=doctor_id).first()
        patient = User.query.filter_by(id=patient_id).first()

        if not doctor or not patient:
            return jsonify({"message": "Doctor or patient do not exist", "successful": False, "status_code": 400}), 400

        status = "pending"
        new_prescription = Presciption(
            date=date,
            doctor_id=doctor_id,
            patient_id=patient_id,
            prescription=prescription_details,
            status=status
        )
        db.session.add(new_prescription)
        db.session.commit()
        return jsonify({"message": "Prescription added successfully", "successful": True, "status_code": 201}), 201
    except Exception as err:
        db.session.rollback()
        return jsonify({"message": f"Failed to add prescription. Error: {err}", "successful": False, "status_code": 500}), 500


@app.route("/users/get/prescription/<int:id>", methods=["GET"])
@jwt_required()
def get_prescriptions(id):
    prescriptions = Presciption.query.filter_by(patient_id=id).all()

    if not prescriptions:
        return jsonify({"message": "You have no precriptions yet", "successful": False, "status_code": 404}), 404
    precriptions_list =[]
    for prescrip in prescriptions:
        doctor = User.query.filter_by(id=prescrip.doctor_id).first()
        precriptions_list.append({
            "id":prescrip.id,
            "doctorId": prescrip.doctor_id,
            "patientId": prescrip.patient_id,
            "date": prescrip.date.isoformat(),
            "prescription": prescrip.prescription,
            "status": prescrip.status,
            "doctorName": f"{doctor.first_name} {doctor.last_name}"
        })

    user_data_json = json.dumps(precriptions_list)
    new_iv = os.urandom(16)
    cipher = AES.new(ENCRYPTION_KEY.encode("utf-8"), AES.MODE_CBC, new_iv)
    padded_user_data = user_data_json + (AES.block_size - len(user_data_json) % AES.block_size) * "\0"
    encrypted_user_data = cipher.encrypt(padded_user_data.encode("utf-8"))

    encrypted_user_data_b64 = base64.b64encode(encrypted_user_data).decode("utf-8")
    iv_b64 = new_iv.hex()

    return jsonify({"ciphertext": encrypted_user_data_b64, "iv": iv_b64, "message": "Data retrived successfully", "status_code": 200, "successful": True}), 200


    # return jsonify({"prescription": precriptions_list, "message": "Prescription retrieved successfully", "successful": True, "status_code": 200}), 200


@app.route("/users/post/impressions", methods=["POST"])
@jwt_required()
def post_impressions():
    data = request.get_json()
    if not data:
        return jsonify({"message": "Empty data", "successful": False, "status_code": 400}), 400
    
    ciphertext = data.get('ciphertext')
    iv = data.get('iv')

    try:
        decrypted_data = decrypt_message(ciphertext, iv)

        impression = json.loads(decrypted_data)

        if not all(key in impression for key in ('date', 'patientId', 'doctorId', 'impression')):
            return jsonify({"message": "Incomplete user data received", "status_code": 400, "successful": False}), 400


        try:
            date = datetime.strptime(impression.get("date"), "%Y-%m-%dT%H:%M:%S.%fZ")
            patient_id = int(impression.get("patientId"))
            doctor_id = int(impression.get("doctorId"))
            impression = str(impression.get("impression"))

        except ValueError as err:
            return jsonify({"message": f"Provide the right data format. Error: {err}", "successful": False, "status_code": 400}), 400

        doctor = User.query.filter_by(id=doctor_id).first()
        patient = User.query.filter_by(id=patient_id).first()

        if not doctor or not patient:
            return jsonify({"message": "Doctor or patient do not exist", "successful": False, "status_code": 400}), 400

        new_impression = Impression(
            date=date,
            doctor_id=doctor_id,
            patient_id=patient_id,
            impresion=impression
        )
        db.session.add(new_impression)
        db.session.commit()
        return jsonify({"message": "Impression added successfully", "successful": True, "status_code": 201}), 201
    except Exception as err:
        db.session.rollback()
        return jsonify({"message": f"Failed to add impression. Error: {err}", "successful": False, "status_code": 500}), 500


@app.route("/users/get/impression/<int:id>", methods=["GET"])
@jwt_required()
def get_impresion(id):
    impressions = Impression.query.filter_by(patient_id=id).all()

    if not impressions:
        return jsonify({"message": "You have no impressions yet", "successful": False, "status_code": 404}), 404
    impressions_list =[]
    for impresion in impressions:
        doctor = User.query.filter_by(id=impresion.doctor_id).first()
        impressions_list.append({
            "id":impresion.id,
            "doctorId": impresion.doctor_id,
            "patientId": impresion.patient_id,
            "date": impresion.date.isoformat(),
            "prescription": impresion.impresion,
            "doctorName": f"{doctor.first_name} {doctor.last_name}"
        })

    user_data_json = json.dumps(impressions_list)
    new_iv = os.urandom(16)
    cipher = AES.new(ENCRYPTION_KEY.encode("utf-8"), AES.MODE_CBC, new_iv)
    padded_user_data = user_data_json + (AES.block_size - len(user_data_json) % AES.block_size) * "\0"
    encrypted_user_data = cipher.encrypt(padded_user_data.encode("utf-8"))

    encrypted_user_data_b64 = base64.b64encode(encrypted_user_data).decode("utf-8")
    iv_b64 = new_iv.hex()

    return jsonify({"ciphertext": encrypted_user_data_b64, "iv": iv_b64, "message": "Data retrived successfully", "status_code": 200, "successful": True}), 200


    # return jsonify({"prescription": impressions_list, "message": "Prescription retrieved successfully", "successful": True, "status_code": 200}), 200


@app.route("/users/post/response", methods=["POST"])
@jwt_required()
def post_response():
    data = request.get_json()
    if not data:
        return jsonify({"message": "Empty data", "successful": False, "status_code": 400}), 400
    
    ciphertext = data.get('ciphertext')
    iv = data.get('iv')

    try:
        decrypted_data = decrypt_message(ciphertext, iv)

        response = json.loads(decrypted_data)

        if not all(key in response for key in ('date', 'patientId', 'responses')):
            return jsonify({"message": "Incomplete user data received", "status_code": 400, "successful": False}), 400

        try:
            date = datetime.strptime(response.get("date"), "%Y-%m-%dT%H:%M:%S.%fZ")
            patient_id = int(response.get("patientId"))
            responses = str(response.get("responses"))

        except ValueError as err:
            return jsonify({"message": f"Provide the right data format. Error: {err}", "successful": False, "status_code": 400}), 400
        patient = User.query.filter_by(id=patient_id).first()

        if not patient:
            return jsonify({"message": "Patient do not exist", "successful": False, "status_code": 400}), 400

        new_response = HealthResponse(
            date=date,
            user_id=patient_id,
            responses=responses
        )
        db.session.add(new_response)
        db.session.commit()
        return jsonify({"message": "Response added successfully", "successful": True, "status_code": 201}), 201
    except Exception as err:
        db.session.rollback()
        return jsonify({"message": f"Failed to add response. Error: {err}", "successful": False, "status_code": 500}), 500


@app.route("/users/get/response", methods=["GET"])
@jwt_required()
def get_response():
    responses = HealthResponse.query.all()

    if not responses:
        return jsonify({"message": "No responses yet", "successful": False, "status_code": 404}), 404
    
    responses_list = []
    
    for response in responses:
        patient = User.query.filter_by(id=response.user_id).first()
        responses_list.append({
            "id": response.id,
            "patientId": response.user_id,
            "patientName": f"{patient.first_name} {patient.last_name}",
            "dateTime": response.date.isoformat(),
            "responses": response.responses
        })

    # return jsonify({"message": "Data retrieved successfully", "data": responses_list, "successful": True, "status_code": 200}), 200
    user_data_json = json.dumps(responses_list)
    new_iv = os.urandom(16)
    cipher = AES.new(ENCRYPTION_KEY.encode("utf-8"), AES.MODE_CBC, new_iv)
    padded_user_data = user_data_json + (AES.block_size - len(user_data_json) % AES.block_size) * "\0"
    encrypted_user_data = cipher.encrypt(padded_user_data.encode("utf-8"))

    encrypted_user_data_b64 = base64.b64encode(encrypted_user_data).decode("utf-8")
    iv_b64 = new_iv.hex()

    return jsonify({"ciphertext": encrypted_user_data_b64, "iv": iv_b64, "message": "Data retrived successfully", "status_code": 200, "successful": True}), 200


@app.route("/users/rating", methods=["POST"])
@jwt_required()
def post_rating_and_remarks():
    data = request.get_json()

    if not data:
        return jsonify({"message": "You provided an empty data", "successful": False, "status_code": 400}), 400
    
    ciphertext = data.get("ciphertext")
    iv = data.get("iv")

    if not ciphertext or not iv:
        return jsonify({"message": "Incomplete data", "successful": False, "status_code": 400}), 400
    
    try:
        decrypted_data = decrypt_message(ciphertext, iv)

        response = json.loads(decrypted_data)

        if not all(key in response for key in ('patientId', 'doctorId', 'remarks', 'rating', "dateTime")):
            return jsonify({"message": "Incomplete data, missing required fields", "successful": False, "status_code": 400}), 400
        
        try:
            doctor_id = int(response.get("doctorId"))
            patient_id = int(response.get("patientId"))
            remarks = str(response.get("remarks"))
            rating = dict(response.get("rating"))
            date = datetime.strptime(response.get("dateTime"), "%Y-%m-%dT%H:%M:%S.%fZ")

        except ValueError as err:
            return jsonify({"message": f"Invalid data type {err}", "successful": False, "status_code": 400}), 400
        
        new_rating = RatingAndRemarks(
            doctor_id=doctor_id,
            patient_id=patient_id,
            remarks=remarks,
            rating=rating,
            date=date
        )

        db.session.add(new_rating)
        db.session.commit()

        return jsonify({"message": "Data added successfully", "successful": True, "status_code": 201}), 201
    except Exception as err:
        db.session.rollback()
        return jsonify({"message": f"Failed to create. Error: {err}", "successful": False, "status_code": 500}), 500
  

@app.route("/users/delete/<int:id>", methods=["DELETE"])
@jwt_required()
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
    

@app.route("/users/doctors", methods=["GET"])
@jwt_required()
def get_users_():
    users = User.query.all()

    users_list = []
    for user in users:
        if user.role == "doctor" and user.status == "active":
            users_list.append({
            "id": user.id,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "role": user.role,
            })

    # return jsonify({"doctors": users_list, "successful": True}), 200

    user_data_json = json.dumps(users_list)
    new_iv = os.urandom(16)
    cipher = AES.new(ENCRYPTION_KEY.encode("utf-8"), AES.MODE_CBC, new_iv)
    padded_user_data = user_data_json + (AES.block_size - len(user_data_json) % AES.block_size) * "\0"
    encrypted_user_data = cipher.encrypt(padded_user_data.encode("utf-8"))

    encrypted_user_data_b64 = base64.b64encode(encrypted_user_data).decode("utf-8")
    iv_b64 = new_iv.hex()

    return jsonify({"ciphertext": encrypted_user_data_b64, "iv": iv_b64, "message": "Data retrived successfully", "status_code": 200, "successful": True}), 200



@app.route("/users/del", methods=["GET"])
@jwt_required()
def remove():
    rm = PatientHistory.query.filter_by(page_no=12).first()

    data_list = []

    if not rm:
        return jsonify({"message": "Not found"}), 404
    
    data_list.append({
        "id":rm.id,
        "userId":rm.user_id,
        "pageNo":rm.page_no,
        "questions":rm.questions,
        "dateTime":rm.date_time.isoformat()
    })
    
    
    return jsonify({"message":"removed successfully", "data": data_list}), 200


@app.route("/users/monitor/<int:id>", methods=["GET"])
@jwt_required()
def monitor_tasks(id):
    tasks = Task.query.filter_by(doctor_id=id).all()

    if not tasks:
        return jsonify({"message": "There are no tasks", "successful":False, "status_code": 404}), 404
    
    tasks_list = []
    
    for task in tasks:
        completed_tasks = CompletedTask.query.filter_by(task_id=task.id).all()


        for completed_task in completed_tasks:
            tasks_list.append({
                "id":completed_task.id,
                "taskId":completed_task.task_id,
                "patientId":completed_task.patient_id,
                "patientName": task.patient_name,
                "dateCompleted": completed_task.completed_time,
                "activity": task.activities,
                "duration": task.duration,
                "frequency": task.frequency
            })

    return jsonify({"message": "Data retrieved successfully", "data": tasks_list, "successful":True, "status_code": 200}), 200


@app.route("/users/remove", methods=["DELETE"])
def remove_history():
    data = PatientHistory.query.all()

    if not data:
        return jsonify({"message": "You have no history", "successful": False, "status_code": 404}), 404
    
    for datum in data:
        db.session.delete(datum)
        db.session.commit()

    return jsonify({"message": "All data deleted", "successful": True, "status_code": 200}), 200



if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5555, debug=True)




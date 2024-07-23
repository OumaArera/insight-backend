from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy.dialects.postgresql import JSONB

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(200), nullable=False)
    last_name = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(15), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(300), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)
    last_login = db.Column(db.DateTime, nullable=False)

class PatientHistory(db.Model):
    __tablename__ = "patients_history"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, ForeignKey('users.id'), nullable=False)
    page_no = db.Column(db.Integer, nullable=False)
    questions = db.Column(JSONB, nullable=False)
    date_time = db.Column(db.DateTime, nullable=False)

    user = db.relationship('User', backref=db.backref('patients_history', lazy=True))

class Task(db.Model):
    __tablename__ = "assigned_tasks"

    id = db.Column(db.Integer, primary_key=True)
    doctor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    patient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    patient_name = db.Column(db.String(200), nullable=False)
    activities = db.Column(JSONB, nullable=False)
    date_time = db.Column(db.DateTime, nullable=False)
    duration = db.Column(db.Float, nullable=False)
    frequency = db.Column(db.Integer, nullable=False)
    
    patient = db.relationship('User', foreign_keys=[patient_id], backref=db.backref('assigned_tasks_as_patient', lazy=True))
    doctor = db.relationship('User', foreign_keys=[doctor_id], backref=db.backref('assigned_tasks_as_doctor', lazy=True))


class CompletedTask(db.Model):
    __tablename__ = "completed_tasks"

    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('assigned_tasks.id'), nullable=False)
    patient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    completed_time = db.Column(db.DateTime, nullable=False)

    patient = db.relationship('User', backref=db.backref('completed_tasks', lazy=True))
    task = db.relationship('Task', backref=db.backref('completed_tasks', lazy=True))


class Session(db.Model):
    __tablename__ = "sessions"
    
    id = db.Column(db.Integer, primary_key=True)
    physician_id = db.Column(db.Integer, ForeignKey('users.id'), nullable=False)
    available = db.Column(db.Boolean, nullable=False)
    location = db.Column(db.String(50), nullable=False)
    meeting_url= db.Column(db.String(200), nullable=True)
    meeting_location= db.Column(db.String(200), nullable=True)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    session_time = db.Column(db.DateTime, nullable=False)
    patient_id = db.Column(db.Integer, nullable=True)

    physician = db.relationship('User', backref=db.backref('sessions', lazy=True))

class Presciption(db.Model):
    __tablename__ = "prescriptions"

    id = db.Column(db.Integer, primary_key=True)
    doctor_id = db.Column(db.Integer, ForeignKey('users.id'), nullable=False)
    patient_id = db.Column(db.Integer, ForeignKey('users.id'), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    prescription = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), nullable=False)

    patient = db.relationship('User', foreign_keys=[patient_id], backref=db.backref('patient_', lazy=True))
    doctor = db.relationship('User', foreign_keys=[doctor_id], backref=db.backref('doctor_', lazy=True))

class Impression(db.Model):
    __tablename__ = "impressions"

    id = db.Column(db.Integer, primary_key=True)
    doctor_id = db.Column(db.Integer, ForeignKey('users.id'), nullable=False)
    patient_id = db.Column(db.Integer, ForeignKey('users.id'), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    impresion = db.Column(db.Text, nullable=False)

    patient = db.relationship('User', foreign_keys=[patient_id], backref=db.backref('impression_', lazy=True))
    doctor = db.relationship('User', foreign_keys=[doctor_id], backref=db.backref('impression', lazy=True))

class HealthResponse(db.Model):
    __tablename__ = "health_responses"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, ForeignKey('users.id'), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    responses = db.Column(JSONB, nullable=False)

    patient = db.relationship('User', backref=db.backref('health_responses', lazy=True))


class RatingAndRemarks(db.Model):
    __tablename__ = "rating_and_remarks"

    id = db.Column(db.Integer, primary_key=True)
    doctor_id = db.Column(db.Integer, ForeignKey('users.id'), nullable=False)
    patient_id = db.Column(db.Integer, ForeignKey('users.id'), nullable=False)
    remarks = db.Column(db.Text, nullable=False)
    rating = db.Column(JSONB, nullable=False)
    date = date = db.Column(db.DateTime, nullable=False)

    patient = db.relationship('User', foreign_keys=[patient_id], backref=db.backref('rating_and_remarks', lazy=True))
    doctor = db.relationship('User', foreign_keys=[doctor_id], backref=db.backref('rating_and_remarks_', lazy=True))
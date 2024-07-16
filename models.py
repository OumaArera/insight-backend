from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from datetime import datetime, timezone
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
    __tablename__ = "tasks"

    id = db.Column(db.Integer, primary_key=True)
    doctor_id = db.Column(db.Integer, ForeignKey('users.id'), nullable=False)
    patient_id = db.Column(db.Integer, ForeignKey('users.id'), nullable=False)
    patient_name= db.Column(db.String(200), nullable=False)
    activities = db.Column(JSONB, nullable=False)
    date_time = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), nullable=False)
    duration = db.Column(db.Float, nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    progress = db.Column(db.Integer, nullable=False)
    remaining_time = db.Column(db.Integer, nullable=False)

    patient = db.relationship('User', foreign_keys=[patient_id], backref=db.backref('patient', lazy=True))
    doctor = db.relationship('User', foreign_keys=[doctor_id], backref=db.backref('doctor', lazy=True))

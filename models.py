from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scans = db.relationship("Scan", backref="user", lazy=True)

    def __repr__(self):
        return f"<User {self.username}>"

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    domain = db.Column(db.String(255), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    grade = db.Column(db.String(2), nullable=False)
    level = db.Column(db.String(50), nullable=False)
    dns_score = db.Column(db.Integer, default=0)
    ssl_score = db.Column(db.Integer, default=0)
    port_score = db.Column(db.Integer, default=0)
    cloud_score = db.Column(db.Integer, default=0)
    email_score = db.Column(db.Integer, default=0)
    issue_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Scan {self.domain} - {self.score}>"
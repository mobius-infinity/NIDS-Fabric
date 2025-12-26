from app import db
from flask_login import UserMixin

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    full_name = db.Column(db.String(150), default='System Admin')
    avatar_file = db.Column(db.String(50), default='admin_default.png')
    theme_preference = db.Column(db.String(20), default='light')
class SystemSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    detection_mode = db.Column(db.String(50), default='voting')
    voting_threshold = db.Column(db.Integer, default=2)
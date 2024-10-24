from app import db
from flask_login import UserMixin
from datetime import datetime, timedelta
import uuid

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # Add relationship to SignedApp
    apps = db.relationship('SignedApp', backref='user', lazy=True, cascade='all, delete-orphan')

class SignedApp(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    app_name = db.Column(db.String(128), nullable=False)
    bundle_id = db.Column(db.String(128), nullable=False)
    ipa_path = db.Column(db.String(256), nullable=False)
    plist_path = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    installation_url = db.Column(db.String(512), nullable=False)
    expiration_date = db.Column(db.DateTime, nullable=False, default=lambda: datetime.utcnow() + timedelta(days=30))
    share_token = db.Column(db.String(64), unique=True, default=lambda: str(uuid.uuid4()))
    is_public = db.Column(db.Boolean, default=False)

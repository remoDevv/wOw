import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from sqlalchemy.orm import DeclarativeBase
from datetime import datetime
import threading
import time

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
login_manager = LoginManager()

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or "a secret key"

# Update database URL to use environment variables
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max file size
app.config['UPLOAD_FOLDER'] = 'static/uploads'

# Initialize extensions
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login'

# Create upload folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize database schema
def init_db():
    with app.app_context():
        import models
        # Only create tables if they don't exist
        db.create_all()

def cleanup_expired_files(app=app):
    """Periodically clean up expired files"""
    while True:
        with app.app_context():
            try:
                from models import SignedApp
                now = datetime.utcnow()
                expired_apps = SignedApp.query.filter(SignedApp.expiration_date < now).all()
                
                for app_item in expired_apps:
                    try:
                        if os.path.exists(app_item.ipa_path):
                            os.remove(app_item.ipa_path)
                        if os.path.exists(app_item.plist_path):
                            os.remove(app_item.plist_path)
                        db.session.delete(app_item)
                    except Exception as e:
                        print(f"Error cleaning up expired app {app_item.id}: {str(e)}")
                
                db.session.commit()
            except Exception as e:
                print(f"Error in cleanup task: {str(e)}")
            
        # Sleep for 1 hour before next cleanup
        time.sleep(3600)

# Start cleanup thread
cleanup_thread = threading.Thread(target=cleanup_expired_files, daemon=True)
cleanup_thread.start()
        
# Initialize database only if tables don't exist
init_db()

@login_manager.user_loader
def load_user(user_id):
    from models import User
    return User.query.get(int(user_id))

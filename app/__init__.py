from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from config import Config

# Khởi tạo các extension (chưa gắn vào app)
db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = 'auth.login' # Tên function login trong auth blueprint
login_manager.login_message_category = 'info'

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Gắn extension vào app
    db.init_app(app)
    login_manager.init_app(app)

    # Đăng ký Blueprints
    from app.auth.routes import auth_bp
    from app.api.routes import api_bp
    from app.main.routes import main_bp

    app.register_blueprint(auth_bp, url_prefix='/auth') # Login sẽ là /auth/login
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(main_bp) # Route gốc /

    return app

# Hàm load user cho Flask-Login
@login_manager.user_loader
def load_user(user_id):
    from app.models import User
    return db.session.get(User, int(user_id))

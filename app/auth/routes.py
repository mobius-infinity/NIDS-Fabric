from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash
from app.models import User

# Tạo Blueprint cho Auth
auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    # Nếu đã login rồi thì chuyển hướng về index
    if current_user.is_authenticated:
        return redirect(url_for('main.index')) # Giả sử main.index là route trang chủ

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user, remember=True)
            # Chuyển hướng đến trang user muốn vào trước đó hoặc trang chủ
            next_page = request.args.get('next')
            return redirect(next_page or url_for('main.index'))
        
        return render_template('login.html', error="Invalid Credentials")
    
    return render_template('login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

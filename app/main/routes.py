from flask import Blueprint, render_template, redirect, url_for
from flask_login import login_required, current_user

# Tạo Blueprint tên là 'main'
main_bp = Blueprint('main', __name__)

@main_bp.route('/')
@login_required
def index():
    # Render trang chủ (Dashboard)
    return render_template('index.html')

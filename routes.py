import requests
import json
from datetime import datetime
from flask import render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import login_user, logout_user, login_required, current_user
from user_agents import parse
from app import app, db, login_manager
from models import User, LoginSession

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def get_geolocation_data(ip_address):
    """Get geolocation data from ip-api.com (free service)"""
    try:
        if ip_address in ['127.0.0.1', 'localhost', '::1']:
            # For local development, use a default location
            return {
                'country': 'Local Development',
                'regionName': 'Development Environment',
                'city': 'Localhost',
                'lat': 0.0,
                'lon': 0.0,
                'timezone': 'UTC',
                'isp': 'Local Network'
            }
        
        # Use ip-api.com free service (no API key required)
        response = requests.get(f'http://ip-api.com/json/{ip_address}', timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                return data
    except Exception as e:
        app.logger.error(f"Error getting geolocation data: {e}")
    
    return None

def get_client_ip():
    """Get the real client IP address"""
    forwarded_for = request.headers.get('X-Forwarded-For')
    if forwarded_for:
        return forwarded_for.split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr

def parse_user_agent(user_agent_string):
    """Parse user agent string to extract browser and OS info"""
    user_agent = parse(user_agent_string)
    return {
        'browser': f"{user_agent.browser.family} {user_agent.browser.version_string}",
        'operating_system': f"{user_agent.os.family} {user_agent.os.version_string}",
        'device_type': 'Mobile' if user_agent.is_mobile else 'Desktop'
    }

def create_login_session(user):
    """Create a new login session with tracking data"""
    ip_address = get_client_ip()
    user_agent_string = request.headers.get('User-Agent', '')
    
    # Get geolocation data
    geo_data = get_geolocation_data(ip_address)
    
    # Parse user agent
    ua_data = parse_user_agent(user_agent_string)
    
    # Create login session
    login_session = LoginSession(
        user_id=user.id,
        ip_address=ip_address,
        user_agent=user_agent_string,
        browser=ua_data['browser'],
        operating_system=ua_data['operating_system'],
        device_type=ua_data['device_type']
    )
    
    # Add geolocation data if available
    if geo_data:
        login_session.country = geo_data.get('country')
        login_session.region = geo_data.get('regionName')
        login_session.city = geo_data.get('city')
        login_session.latitude = geo_data.get('lat')
        login_session.longitude = geo_data.get('lon')
        login_session.timezone = geo_data.get('timezone')
        login_session.isp = geo_data.get('isp')
    
    db.session.add(login_session)
    db.session.commit()
    
    # Store session ID in Flask session for logout tracking
    session['login_session_id'] = login_session.id
    
    return login_session

@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not email or not password:
            flash('Please provide both email and password.', 'error')
            return render_template('login.html')
        
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            login_user(user, remember=True)
            
            # Create login session with tracking
            create_login_session(user)
            
            flash(f'Welcome back, {user.email}!', 'success')
            
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid email or password.', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not all([email, password, confirm_password]):
            flash('Please fill in all fields.', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')
        
        if password and len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return render_template('register.html')
        
        # Check if user already exists
        if User.query.filter_by(email=email).first():
            flash('Email address already registered.', 'error')
            return render_template('register.html')
        
        # Create new user
        user = User(email=email)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    # Update logout time for current session
    if 'login_session_id' in session:
        login_session = LoginSession.query.get(session['login_session_id'])
        if login_session:
            login_session.logout_time = datetime.utcnow()
            login_session.is_active = False
            
            # Calculate session duration
            if login_session.login_time:
                duration = (login_session.logout_time - login_session.login_time).total_seconds()
                login_session.session_duration = int(duration)
            
            db.session.commit()
        
        session.pop('login_session_id', None)
    
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def user_dashboard():
    # Get user's login sessions
    sessions = LoginSession.query.filter_by(user_id=current_user.id).order_by(LoginSession.login_time.desc()).all()
    return render_template('user_dashboard.html', sessions=sessions)

@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('user_dashboard'))
    
    # Get all login sessions for admin view
    sessions = LoginSession.query.join(User).order_by(LoginSession.login_time.desc()).all()
    users = User.query.all()
    
    return render_template('admin_dashboard.html', sessions=sessions, users=users)

@app.route('/admin/sessions')
@login_required
def admin_sessions():
    if not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403
    
    sessions = LoginSession.query.join(User).order_by(LoginSession.login_time.desc()).all()
    return jsonify([session.to_dict() for session in sessions])

@app.route('/admin/make_admin/<int:user_id>')
@login_required
def make_admin(user_id):
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('user_dashboard'))
    
    user = User.query.get_or_404(user_id)
    user.is_admin = True
    db.session.commit()
    
    flash(f'{user.email} is now an admin.', 'success')
    return redirect(url_for('admin_dashboard'))
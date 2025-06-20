from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship to login sessions
    login_sessions = db.relationship('LoginSession', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.email}>'

class LoginSession(db.Model):
    __tablename__ = 'login_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # IP and location data
    ip_address = db.Column(db.String(45))  # IPv6 can be up to 45 chars
    user_agent = db.Column(db.Text)
    
    # Geolocation data
    country = db.Column(db.String(100))
    region = db.Column(db.String(100))
    city = db.Column(db.String(100))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    timezone = db.Column(db.String(100))
    isp = db.Column(db.String(200))
    
    # Browser and device info
    browser = db.Column(db.String(100))
    operating_system = db.Column(db.String(100))
    device_type = db.Column(db.String(50))
    
    # Session tracking
    login_time = db.Column(db.DateTime, default=datetime.utcnow)
    logout_time = db.Column(db.DateTime)
    session_duration = db.Column(db.Integer)  # in seconds
    is_active = db.Column(db.Boolean, default=True)
    
    def __repr__(self):
        return f'<LoginSession {self.user_id} from {self.ip_address}>'
    
    def to_dict(self):
        user_email = self.user.email if self.user else 'Unknown'
        return {
            'id': self.id,
            'user_email': user_email,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'country': self.country,
            'region': self.region,
            'city': self.city,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'timezone': self.timezone,
            'isp': self.isp,
            'browser': self.browser,
            'operating_system': self.operating_system,
            'device_type': self.device_type,
            'login_time': self.login_time.isoformat() if self.login_time else None,
            'logout_time': self.logout_time.isoformat() if self.logout_time else None,
            'session_duration': self.session_duration,
            'is_active': self.is_active
        }from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship to login sessions
    login_sessions = db.relationship('LoginSession', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.email}>'

class LoginSession(db.Model):
    __tablename__ = 'login_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # IP and location data
    ip_address = db.Column(db.String(45))  # IPv6 can be up to 45 chars
    user_agent = db.Column(db.Text)
    
    # Geolocation data
    country = db.Column(db.String(100))
    region = db.Column(db.String(100))
    city = db.Column(db.String(100))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    timezone = db.Column(db.String(100))
    isp = db.Column(db.String(200))
    
    # Browser and device info
    browser = db.Column(db.String(100))
    operating_system = db.Column(db.String(100))
    device_type = db.Column(db.String(50))
    
    # Session tracking
    login_time = db.Column(db.DateTime, default=datetime.utcnow)
    logout_time = db.Column(db.DateTime)
    session_duration = db.Column(db.Integer)  # in seconds
    is_active = db.Column(db.Boolean, default=True)
    
    def __repr__(self):
        return f'<LoginSession {self.user_id} from {self.ip_address}>'
    
    def to_dict(self):
        user_email = self.user.email if self.user else 'Unknown'
        return {
            'id': self.id,
            'user_email': user_email,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'country': self.country,
            'region': self.region,
            'city': self.city,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'timezone': self.timezone,
            'isp': self.isp,
            'browser': self.browser,
            'operating_system': self.operating_system,
            'device_type': self.device_type,
            'login_time': self.login_time.isoformat() if self.login_time else None,
            'logout_time': self.logout_time.isoformat() if self.logout_time else None,
            'session_duration': self.session_duration,
            'is_active': self.is_active
        }
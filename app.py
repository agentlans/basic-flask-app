import os
import secrets
import re
from flask import Flask, request, render_template, redirect, url_for, flash, session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
from flask_wtf.csrf import CSRFProtect
from argon2 import PasswordHasher
from sqlalchemy import create_engine, Column, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps

# Configuration
class Config:
    DATABASE_URI = 'sqlite:///users.db'
    PASSWORD_PEPPER = os.environ.get('PASSWORD_PEPPER', 'default_pepper')
    SECRET_KEY = os.environ.get('SECRET_KEY', 'default_secret_key')
    DEBUG = False
    TESTING = False

# Database setup
Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    username = Column(String, primary_key=True)
    password_hash = Column(String, nullable=False)
    salt = Column(String, nullable=False)

# Form classes
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Utility functions
def is_password_strong(password):
    return all([
        len(password) >= 12,
        re.search(r'[A-Z]', password),
        re.search(r'[a-z]', password),
        re.search(r'\d', password),
        re.search(r'[!@#$%^&*(),.?":{}|<>]', password)
    ])

# Database operations
class DatabaseManager:
    def __init__(self, db_uri):
        self.engine = create_engine(db_uri)
        self.Session = sessionmaker(bind=self.engine)
        Base.metadata.create_all(self.engine)

    def add_user(self, username, password_hash, salt):
        with self.Session() as session:
            new_user = User(username=username, password_hash=password_hash, salt=salt)
            session.add(new_user)
            session.commit()

    def get_user(self, username):
        with self.Session() as session:
            return session.query(User).filter_by(username=username).first()

# Password management
class PasswordManager:
    def __init__(self, pepper):
        self.ph = PasswordHasher()
        self.pepper = pepper

    def hash_password(self, password, salt):
        return self.ph.hash(password + salt + self.pepper)

    def verify_password(self, password, stored_hash, salt):
        try:
            return self.ph.verify(stored_hash, password + salt + self.pepper)
        except:
            return False

    @staticmethod
    def generate_salt():
        return secrets.token_hex(16)

# Flask app setup
def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    csrf = CSRFProtect(app)
    
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["200 per day", "50 per hour"]
    )
    
    db_manager = DatabaseManager(app.config['DATABASE_URI'])
    password_manager = PasswordManager(app.config['PASSWORD_PEPPER'])
    
    # Decorator for routes that require login
    def login_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please log in to access this page', 'warning')
                return redirect(url_for('login', next=request.url))
            return f(*args, **kwargs)
        return decorated_function

    @app.route('/')
    def home():
        return render_template('home.html')

    @app.route('/register', methods=['GET', 'POST'])
    @limiter.limit("5 per minute")
    def register():
        form = RegistrationForm()
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data

            if not is_password_strong(password):
                flash('Password does not meet strength requirements', 'error')
                return render_template('register.html', form=form)

            if db_manager.get_user(username):
                flash('Username already exists', 'error')
                return render_template('register.html', form=form)

            try:
                salt = PasswordManager.generate_salt()
                password_hash = password_manager.hash_password(password, salt)
                db_manager.add_user(username, password_hash, salt)
                flash('User registered successfully', 'success')
                return redirect(url_for('login'))
            except Exception as e:
                app.logger.error(f"Error during registration: {str(e)}")
                flash('An error occurred during registration', 'error')

        return render_template('register.html', form=form)

    @app.route('/login', methods=['GET', 'POST'])
    @limiter.limit("10 per minute")
    def login():
        form = LoginForm()
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data

            user = db_manager.get_user(username)
            if user and password_manager.verify_password(password, user.password_hash, user.salt):
                session['user_id'] = user.username
                flash('Logged in successfully', 'success')
                next_page = request.args.get('next')
                return redirect(next_page or url_for('dashboard'))
            else:
                flash('Invalid username or password', 'error')

        return render_template('login.html', form=form)

    @app.route('/logout')
    def logout():
        session.pop('user_id', None)
        flash('You have been logged out', 'info')
        return redirect(url_for('home'))

    @app.route('/dashboard')
    @login_required
    def dashboard():
        return render_template('dashboard.html', username=session['user_id'])

    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('404.html'), 404

    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template('500.html'), 500

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(ssl_context='adhoc')  # Use 'adhoc' for development HTTPS


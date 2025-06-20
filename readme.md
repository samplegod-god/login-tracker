# Login Tracker Application

A Flask-based web application that tracks user login sessions with detailed geolocation, IP, and device information.

## Features

- User registration and authentication
- Automatic geolocation tracking (IP, city, country, coordinates)
- Device and browser information capture
- Session duration tracking
- Admin dashboard to view all user login details
- User dashboard to view personal login history
- PostgreSQL database for data storage

## Installation

1. Install Python dependencies:
```bash
pip install flask flask-sqlalchemy flask-login werkzeug requests user-agents psycopg2-binary gunicorn
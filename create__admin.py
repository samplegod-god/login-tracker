#!/usr/bin/env python3
"""
Script to create an admin user for the login tracking application
"""

from app import app, db
from models import User

def create_admin_user(email, password):
    with app.app_context():
        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            print(f"User {email} already exists!")
            return existing_user
        
        # Create new admin user
        admin_user = User(email=email, is_admin=True)
        admin_user.set_password(password)
        
        db.session.add(admin_user)
        db.session.commit()
        
        print(f"Admin user created successfully: {email}")
        return admin_user

if __name__ == "__main__":
    # Create admin user
    admin_email = "admin@tracker.com"
    admin_password = "admin123"
    
    create_admin_user(admin_email, admin_password)
    
    # Create a regular test user
    test_email = "user@tracker.com"
    test_password = "user123"
    
    with app.app_context():
        existing_test = User.query.filter_by(email=test_email).first()
        if not existing_test:
            test_user = User(email=test_email, is_admin=False)
            test_user.set_password(test_password)
            db.session.add(test_user)
            db.session.commit()
            print(f"Test user created successfully: {test_email}")
        else:
            print(f"Test user {test_email} already exists!")
    
    print("\nLogin credentials:")
    print(f"Admin: {admin_email} / {admin_password}")
    print(f"User: {test_email} / {test_password}")
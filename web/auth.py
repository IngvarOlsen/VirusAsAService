from flask import Blueprint, render_template, request, flash, redirect, url_for, session, make_response
from .models import User  # Importing the User model from the local models module
from werkzeug.security import generate_password_hash, check_password_hash
from . import db  # Importing the database object from the local module
from flask_login import login_user, login_required, logout_user, current_user
import secrets

auth = Blueprint('auth', __name__)  # Creating a Blueprint named 'auth'

def clear_all_cookies(response):
    for cookie in request.cookies:
        print("clear_all_cookies")
        response.delete_cookie(cookie)
    return response

# @auth.after_request
# def clear_cookies_after_request(response):
#     if 'clear_cookies' in session:  # Check if cookies need to be cleared
#         for cookie in request.cookies:
#             response.set_cookie(cookie, '', expires=0)
#         session.pop('clear_cookies')  # Remove the flag after clearing cookies
#     return response

@auth.route('/login', methods=['GET', 'POST'])
def login():
    print("Login route called")
    if request.method == 'POST':  # Check if the request method is POST
        print("Login route called with POST")
        email = request.form.get('email')  # Get the value of 'email' from the form data
        password = request.form.get('password')  # Get the value of 'password' from the form data

        user = User.query.filter_by(email=email).first()  # Query the database for a user with the provided email
        if user:  # If a user with the email is found
            if check_password_hash(user.password, password):  # Check if the provided password matches the hashed password stored in the database

                # Generate the session token and which will be used to access all APIs on website more securly
                token = secrets.token_hex(32)
                print(token)
                
                user.token = token 
                db.session.commit()
                session['token'] = token
                flash('Logged in successfully!', category='success')  # Display a flash message indicating successful login
                logout_user()
                login_user(user, remember=False)
                #login_user(user, remember=True)  # Log in the user and remember the session
                return redirect(url_for('views.virus'))  # Redirect the user to the home page
            else:  # If the password doesn't match
                flash('Incorrect password, try again.', category='error')  # Display a flash message indicating incorrect password
        else:  # If no user with the email is found
            flash('Email does not exist.', category='error')  # Display a flash message indicating that the email doesn't exist

    return render_template("login.html", user=current_user)  # Render the login template with the current user

@auth.route('/logout')
@login_required  # Ensure that the user must be logged in to access this route
def logout():
    # Clears any cookies to avoid old tokens which will cause login errors
    response = make_response(redirect(url_for('auth.login')))
    response = clear_all_cookies(response)
    logout_user()  # Log out the current user
    return redirect(url_for('auth.login'))  # Redirect the user to the login page


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':  # Check if the request method is POST
         # Clears any cookies to avoid old tokens which will cause login errors, in case there was a session cookie already
        response = make_response(redirect(url_for('views.virus')))
        response = clear_all_cookies(response)
        
        print(request.form)
        email = request.form.get('email')  # Get the value of 'email' from the form data
        # name = request.form.get('name')
        password1 = request.form.get('password1')  # Get the value of 'password1' from the form data
        password2 = request.form.get('password2')  # Get the value of 'password2' from the form data

        user = User.query.filter_by(email=email).first()  # Query the database for a user with the provided email
        if user:  # If a user with the email already exists
            flash('Email already exists.', category='error')  # Display a flash message indicating that the email already exists
        elif len(email) < 4:  # If the length of the email is less than 4 characters
            flash('Email must be greater than 3 characters.', category='error')  # Display a flash message indicating that the email is too short
        # elif len(name) < 2:  # If the length of the name is less than 2 characters
        #     flash('First name must be greater than 1 character.', category='error')
        elif password1 != password2:  # If the two password fields don't match
            flash('Passwords don\'t match.', category='error')  # Display a flash message indicating that the passwords don't match
        elif len(password1) < 7:  # If the length of the password is less than 7 characters
            flash('Password must be at least 7 characters.', category='error')  # Display a flash message indicating that the password is too short
        else:  # If all the validation checks pass
 
            # new_user = User(email=email, first_name=name, password=generate_password_hash(
            #     password1, method='sha256'))
            new_user = User(email=email, password=generate_password_hash(
                password1))  # Create a new User object with the provided email and hashed password
            db.session.add(new_user)  # Add the new user to the database session
            db.session.commit()  # Commit the changes to the database
            logout_user()
            token = secrets.token_hex(32)
            new_user.token = token 
            db.session.commit()
            login_user(new_user, remember=False)  # Log in the new user and remember the session
            session['token'] = token
            flash('Account created!', category='success')  # Display a flash message indicating successful account creation
            return redirect(url_for('views.virus'))  # Redirect the user to the home page

    return render_template("login.html", user=current_user)  # Render the login template with the current user
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from os import path
from flask_login import LoginManager
from werkzeug.security import generate_password_hash
import os
import secrets  # Ensure secrets is imported for generating tokens

db = SQLAlchemy()
DB_NAME = "database.db"

# Import models directly for use in setup_demo_data
from .models import User, Virus, Hosts, CompilingHandler

# Is there is no secret key it will create one, instead of just hardcoding it
def get_or_generate_secret_key():
    secret_file = "secret_key.txt"
    if os.path.exists(secret_file):
        with open(secret_file, "r") as f:
            return f.read().strip()
    else:
        secret = os.urandom(24).hex()
        with open(secret_file, "w") as f:
            f.write(secret)
        return secret

def setup_demo_data():
    print("Setting up demo data...")

    # Check if the demo user already exists
    demo_user = User.query.filter_by(email="demo@demo.com").first()
    if not demo_user:
        # Create the demo user
        demo_user = User(
            email="demo@demo.com",
            password=generate_password_hash("demopassword"),
            token=secrets.token_hex(32) 
        )
        db.session.add(demo_user)
        db.session.commit()
        print("Demo user created")

        # Create a test virus for the demo user
        test_virus = Virus(
            name="Demo Virus",
            heartbeat_rate="10",
            use_case_settings="Ransomware Simulation,DNS Tunneling,Net.exe Recon,DLL Side Loading,Registry Edits,Scheduled Tasks,Encrypted Traffic,Traffic on none standard ports",
            user_id=demo_user.id,
            is_alive=True,
            virus_api="superSecretApiKey",
            storage_path=None  # Initially no compiled virus
        )
        db.session.add(test_virus)
        db.session.commit()
        print("Demo virus created.")

        # Create a test host for the demo virus
        test_host = Hosts(
            host_name="DemoHost",
            last_heartbeat="Never",
            user_id=demo_user.id,
            virus_id=test_virus.id,
            log_info="Initial log data for demo host"
        )
        db.session.add(test_host)
        db.session.commit()
        print("Demo host created.")

                # Create a test host for the demo virus
        test_compiling_job = CompilingHandler(
            user_id=demo_user.id,
            virus_id=test_virus.id,
            status="pending"
        )
        db.session.add(test_compiling_job)
        db.session.commit()
        print("Demo pending job created")
    else:
        print("Demo data already exists.")

def create_app(): # Creates and configures a flask app
    print("create_app")
    app = Flask(__name__) # Initialize Flask instance
    # Generates a app secret if there is none, gets used for session handling
    app.config['SECRET_KEY'] = get_or_generate_secret_key() # Makes new key if there is none
    print(app.config['SECRET_KEY'])
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}' # Local SQLite DB
    db.init_app(app) # Bind DB to this app instance
    from .views import views # Frontend routes
    from .auth import auth # Auth routes
    from .api import api # API routes
    app.register_blueprint(views, url_prefix='/') # Registers views
    app.register_blueprint(auth, url_prefix='/') # Register auth blueprint
    app.register_blueprint(api, url_prefix='/') # Register API blueprint
    from .models import User, Virus, Hosts, Archived # Import models from DB
    with app.app_context():
        db.create_all() # Create tables if they dont exist
        setup_demo_data()  # Insert demo data on startup
    login_manager = LoginManager() # flask-login manager
    login_manager.login_view = 'auth.login' # Redirect for unauthenticated access
    login_manager.init_app(app) # Attach login_manager to app
    @login_manager.user_loader
    def load_user(id): # Internal funnktion returns ID of logged in user
        return User.query.get(int(id))
    return app # Return the configured flask application


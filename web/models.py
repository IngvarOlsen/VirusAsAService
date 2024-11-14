from . import db
from flask_login import UserMixin
from sqlalchemy.sql import func

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))

class Virus(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(500))
    heartbeat_rate = db.Column(db.String(500))
    use_case_settings = db.Column(db.String(500))
    user_id = db.Column(db.String(150))
    #If virus is not alive it will kill itself upon update and data will be movre to archived
    is_alive = db.Column(db.Boolean, unique=False, default=True) 

class Hosts(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    host_notes = db.Column(db.String(500))
    last_heartbeat = db.Column(db.String(500))
    user_id = db.Column(db.String(150))
    virus_id = db.Column(db.String(150))
    log_info = db.Column(db.String(150))

class Archived(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    log_name = db.Column(db.String(500))
    virus_id = db.Column(db.String(150))
    user_id = db.Column(db.String(150))

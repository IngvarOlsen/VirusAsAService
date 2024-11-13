import requests
from flask import Blueprint, render_template, request, flash, jsonify, send_file
from flask_login import login_required, current_user
#from .models import Note, ImageSet, Image
from .models import Virus, Hosts
import sqlite3
from . import db
import json
import os
import socketio



## Ignore temp lack of ssl
os.environ['CURL_CA_BUNDLE'] = ''


api = Blueprint('api', __name__)
userToken = '1234567890'

def dbConnect():
    global conn
    #conn = sqlite3.connect('/var/www/instance/database.db')
    conn = sqlite3.connect('instance/database.db')
    global curs
    curs = conn.cursor()




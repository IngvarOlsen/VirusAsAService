from flask import Blueprint, render_template, request, flash, jsonify
from flask_login import login_required, current_user
from sqlalchemy import Table, select, join, MetaData
from sqlalchemy.orm import joinedload
#from .models import Note, ImageSet, Image
from .models import Virus, Hosts, Archived
from . import db #, session
import json
import os
#Import apy.py
from . import api
import collections

views = Blueprint('views', __name__)

@views.route('/', methods=['GET', 'POST'], endpoint='home')
@login_required
def home():
    return render_template("home.html", user=current_user)


@views.route('/hosts', methods=['GET', 'POST'])
@login_required
def hosts():
    print(current_user.id)
    #dataToHtml = api.getHosts(str(current_user.id), "1234567890") #In real
    dataToSend = api.getHosts() # debug for user1
    print(dataToSend)

    return render_template("home.html", user=current_user, dataToHtml = dataToSend)

@views.route('/virus', methods=['GET', 'POST'])
@login_required
def virus():
    print(current_user.id)
    dataToSend = api.getActiveVirus() 
    print(dataToSend)

    return render_template("virus.html", user=current_user, dataToHtml = dataToSend)


@views.route('/archived', methods=['GET', 'POST'])
@login_required
def archived():
    try:
        # Query to join Archived and Virus
        archived_viruses = db.session.query(Archived, Virus).join(
            Virus, Archived.virus_id == Virus.id
        ).filter(Archived.user_id == current_user.id).all()

        # Format the data for the template
        data_to_send = [
            {
                'archived_id': archived.id,
                'log_name': archived.log_name,
                'virus_name': virus.name,
                'heartbeat_rate': virus.heartbeat_rate,
                'use_case_settings': virus.use_case_settings,
                'virus_id': virus.id,
            }
            for archived, virus in archived_viruses
        ]

        print(data_to_send) 

        return render_template("archived.html", user=current_user, dataToHtml=data_to_send)

    except Exception as e:
        print(f"Error retrieving archived viruses: {e}")
        flash('Failed to load archived viruses.', category='error')
        return redirect(url_for('views.virus'))  

    
@views.route('/authtest', methods=['GET', 'POST'])
# @login_required
def authTest():
    return render_template("authtest.html", user=current_user)
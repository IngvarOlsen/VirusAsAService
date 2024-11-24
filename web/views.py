from flask import Blueprint, render_template, request, flash, jsonify, redirect, url_for
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

# @views.route('/', methods=['GET', 'POST'], endpoint='home')
# @login_required
# def home():
#     token = request.args.get('token')  # Retrieve the token from the query parameter
#     print(f"Token received: {token}")  # Debugging output
#     return render_template("home.html", user=current_user)


@views.route('/hosts', methods=['GET', 'POST'])
@login_required
def hosts():
    print(current_user.id)
    #dataToHtml = api.getHosts(str(current_user.id), "1234567890") #In real
    dataToSend = api.getHosts() # debug for user1
    print(dataToSend)

    return render_template("hosts.html", user=current_user, dataToHtml = dataToSend)

# @views.route('/', methods=['GET', 'POST'])
# @views.route('/virus', methods=['GET', 'POST'])
# @login_required
# def virus():
#     print(current_user.id)
#     dataToSend = api.getActiveVirus() 
#     print(dataToSend)

#     return render_template("virus.html", user=current_user, dataToHtml = dataToSend)

@views.route('/', methods=['GET', 'POST'])
@views.route('/virus', methods=['GET', 'POST'])
@login_required
def virus():
    print(f"User ID: {current_user.id}")

    try:
        # Validate the token
        if not api.validateToken():
            flash("Invalid token. Please log in again.", category="error")
            return redirect(url_for("auth.login"))

        # Query the database using SQLAlchemy
        active_viruses = Virus.query.filter_by(user_id=current_user.id, is_alive=True).all()

        # Format the data as a list of dictionaries
        dataToSend = [
            {
                'id': virus.id,
                'name': virus.name,
                'heartbeat_rate': virus.heartbeat_rate,
                'use_case_settings': virus.use_case_settings,
                'user_id': virus.user_id,
                'is_alive': virus.is_alive,
            }
            for virus in active_viruses
        ]

        print("Formatted Data:", dataToSend)

        # Render the template with the fetched data
        return render_template("virus.html", user=current_user, dataToHtml=dataToSend)

    except Exception as e:
        # Handle exceptions and redirect to home
        print(f"Error loading virus view: {e}")
        flash("Failed to load active viruses.", category="error")
        return redirect(url_for("views.hosts"))


@views.route('/archived', methods=['GET', 'POST'])
@login_required
def archived():
    try:
        # Query to join Archived, Virus, and Hosts
        archived_viruses = (
            db.session.query(Archived, Virus, Hosts)
            .join(Virus, Archived.virus_id == Virus.id)
            .outerjoin(Hosts, Virus.id == Hosts.virus_id)  # Use outer join to include viruses without hosts
            .filter(Archived.user_id == current_user.id)
            .all()
        )

        # Format the data for the template
        data_to_send = {}
        for archived, virus, host in archived_viruses:
            virus_id = virus.id
            if virus_id not in data_to_send:
                # Initialize data for this virus
                data_to_send[virus_id] = {
                    'archived_id': archived.id,
                    'log_name': archived.log_name,
                    'virus_name': virus.name,
                    'heartbeat_rate': virus.heartbeat_rate,
                    'use_case_settings': virus.use_case_settings,
                    'virus_id': virus.id,
                    'hosts': [],
                }

            # Append host data if available
            if host:
                data_to_send[virus_id]['hosts'].append({
                    'host_name': host.host_name,
                    'last_heartbeat': host.last_heartbeat,
                    'log_info': host.log_info,
                })

        # Convert the data_to_send to a list for easier rendering
        data_to_send_list = list(data_to_send.values())

        print(data_to_send_list)

        return render_template(
            "archived.html",
            user=current_user,
            dataToHtml=data_to_send_list
        )

    except Exception as e:
        print(f"Error retrieving archived viruses: {e}")
        flash('Failed to load archived viruses.', category='error')
        return redirect(url_for('views.virus'))

@views.route('/virusinfo', methods=['POST'])
@login_required
def virusInfo():
    try:
        virus_id = request.form.get("virus_id")
        print("virus_id: ", virus_id)
        # Query the Virus by ID and ensure it belongs to the current user
        virus = Virus.query.filter_by(id=virus_id, user_id=current_user.id).first()
        if not virus:
            flash('Virus not found or unauthorized.', category='error')
            return redirect(url_for('views.virus'))

        # Query all Hosts related to this Virus
        hosts = Hosts.query.filter_by(virus_id=virus_id).all()

        # Format data for the template
        data_to_send = {
            'virus': {
                'id': virus.id,
                'name': virus.name,
                'heartbeat_rate': virus.heartbeat_rate,
                'use_case_settings': virus.use_case_settings,
                'is_alive': virus.is_alive,
            },
            'hosts': [
                {
                    'id': host.id,
                    'host_name': host.host_name,
                    'last_heartbeat': host.last_heartbeat,
                    'log_info': host.log_info,
                }
                for host in hosts
            ]
        }
        # Debugging output
        print(data_to_send)

        return render_template('virusinfo.html', data=data_to_send, user=current_user)

    except Exception as e:
        print(f"Error retrieving virus info: {e}")
        flash('Failed to load virus info.', category='error')
        return redirect(url_for('views.virus'))

    
@views.route('/authtest', methods=['GET', 'POST'])
# @login_required
def authTest():
    return render_template("authtest.html", user=current_user)
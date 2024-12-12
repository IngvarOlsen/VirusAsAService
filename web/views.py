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
import requests

views = Blueprint('views', __name__)

# @views.route('/', methods=['GET', 'POST'], endpoint='home')
# @login_required
# def home():
#     token = request.args.get('token')  # Retrieve the token from the query parameter
#     print(f"Token received: {token}")  # Debugging output
#     return render_template("home.html", user=current_user)

# Helper function to allow both external and localhost calls
def get_base_url():
    external_url = "https://bitlus.online"
    local_url = "http://127.0.0.1"
    try:
        # Try reaching the external domain
        response = requests.head(external_url, timeout=2) 
        if response.status_code == 200:
            print(f"External domain '{external_url}' is reachable.")
            return external_url
    except requests.RequestException:
        print(f"External domain '{external_url}' is not reachable. Falling back to localhost.")
    # Fallback to localhost
    print(local_url)
    return local_url
base_url = get_base_url()


@views.route('/hosts', methods=['GET', 'POST'])
@login_required
def hosts():
    print(current_user.id)
    #dataToHtml = api.getHosts(str(current_user.id), "1234567890") #In real
    data_to_send = api.get_hosts() # debug for user1
    print(data_to_send)

    return render_template("hosts.html", user=current_user, dataToHtml = data_to_send)

# @views.route('/', methods=['GET', 'POST'])
# @views.route('/virus', methods=['GET', 'POST'])
# @login_required
# def virus():
#     print(current_user.id)
#     data_to_send = api.getActiveVirus() 
#     print(data_to_send)

#     return render_template("virus.html", user=current_user, dataToHtml = data_to_send)

@views.route('/', methods=['GET', 'POST'])
@views.route('/virus', methods=['GET', 'POST'])
@login_required
def virus():
    print(f"User ID: {current_user.id}")
    try:
        # Default filter is just all
        filter_option = request.form.get('filter', 'all')
        # Validate the token
        if not api.validate_token():
            flash("Invalid token. Please log in again.", category="error")
            return redirect(url_for("auth.login"))

        # Query the database using SQLAlchemy

        if filter_option == 'active':
            viruses = Virus.query.filter_by(user_id=current_user.id, is_alive=True).all()
        elif filter_option == 'inactive':
            viruses = Virus.query.filter_by(user_id=current_user.id, is_alive=False).all()
        else:  # 'all' or no filter
            viruses = Virus.query.filter_by(user_id=current_user.id).all()

        #viruses = Virus.query.filter_by(user_id=current_user.id, is_alive=True).all()

        # Format the data as a list of dictionaries
        data_to_send = [
            {
                'id': virus.id,
                'name': virus.name,
                'heartbeat_rate': virus.heartbeat_rate,
                'use_case_settings': virus.use_case_settings,
                'user_id': virus.user_id,
                'is_alive': virus.is_alive,
            }
            for virus in viruses
        ]

        print("Formatted Data:", data_to_send)

        # If the request is POST, return the filtered HTML for AJAX update
        if request.method == 'POST':
            print("POST used")
            return render_template('partials/virus_list.html', dataToHtml=data_to_send)

        # For initial GET request, render the entire page
        return render_template('virus.html', user=current_user, dataToHtml=data_to_send)




        # Render the template with the fetched data
        # return render_template("virus.html", user=current_user, dataToHtml=data_to_send)

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
def virus_info():
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
            "url": base_url,
            'virus': {
                'id': virus.id,
                'name': virus.name,
                'heartbeat_rate': virus.heartbeat_rate,
                'use_case_settings': virus.use_case_settings,
                'is_alive': virus.is_alive,
                'virus_api': virus.virus_api,
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
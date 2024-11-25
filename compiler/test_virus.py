import time
import requests
import logging
import socket # Only gets used to get hostname 

# Configurable Variables
API_KEY = "4f300d801d8a81426755f5d09d2e0db613580d88dbbe6d6359e2f98f49c97019"  
USE_CASES = {'ransomware_simulation': True, 'encrypted_traffic': True, 'dns_tunneling': False, 'net_recon': False, 'dll_side_loading': False, 'registry_edits': False, 'scheduled_tasks': False, 'traffic_non_standard_ports': False}

heartbeatRate = 11  # in seconds

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
    import os
    try:
        os.remove(__file__)
        print("Self-deletion complete.")
    except Exception as e:
        logging_func(f"Error in self-deletion: {e}")


# Use Case Functions
def ransomware_simulation():
    logging_func("Executing ransomware simulation.")
    return {"use_case": "ransomware_simulation", "status": "completed"}

def dns_tunneling():
    logging_func("Executing DNS tunneling simulation.")
    return {"use_case": "dns_tunneling", "status": "completed"}

def net_recon():
    logging_func("net recon simulation.")
    return {"use_case": "net_recon", "status": "completed"}

def dll_side_loading():
    logging_func("DLL side loading simulation.")
    return {"use_case": "dll_side_loading", "status": "completed"}

def registry_edits():
    logging_func("registry edits loading simulation.")
    return {"use_case": "registry_edits", "status": "completed"}

def scheduled_tasks():
    logging_func("scheduled tasks simulation.")
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
    try:
        while True:
            response = requests.post(
                "http://127.0.0.1:5000/api/heartbeat",
                headers={"Authorization": API_KEY},
            )
            print(response)
            if response.status_code == 200:
                print(response.json())
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
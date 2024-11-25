import time
import requests
import logging

# Configurable Variables
API_KEY = "f783f3021e9f4c9c217e4a5de5d00e025b93ca91245b3a9bfdd27424d2f21664"  
USE_CASES = {'ransomware_simulation': True, 'dns_tunneling': True, 'encrypted_traffic': True, 'traffic_non_standard_ports': True, 'net_recon': False, 'dll_side_loading': False, 'registry_edits': False, 'scheduled_tasks': False}

heartbeatRate = 11  # in seconds

# Helper Functions
def loggingFunc(log_data):
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

def cleanUp():
    try:
        for use_case, enabled in USE_CASES.items():
            if enabled:
                loggingFunc(f"Cleaning up changes for {use_case}.")
                # Add specific cleanup code for each use case here
        loggingFunc("Cleanup completed. Deleting self.")

        # Self-delete
        # deleteSelf()

    except Exception as e:
        loggingFunc(f"Error during cleanup: {e}")


def dataToSend(data):

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


def deleteSelf():

    import os
    try:
        os.remove(__file__)
        print("Self-deletion complete.")
    except Exception as e:
        loggingFunc(f"Error in self-deletion: {e}")


# Use Case Functions
def ransomware_simulation():
    loggingFunc("Executing ransomware simulation.")
    return {"use_case": "ransomware_simulation", "status": "completed"}

def dns_tunneling():
    loggingFunc("Executing DNS tunneling simulation.")
    return {"use_case": "dns_tunneling", "status": "completed"}

def net_recon():
    loggingFunc("net recon simulation.")
    return {"use_case": "net_recon", "status": "completed"}

def dll_side_loading():
    loggingFunc("DLL side loading simulation.")
    return {"use_case": "dll_side_loading", "status": "completed"}

def registry_edits():
    loggingFunc("registry edits loading simulation.")
    return {"use_case": "registry_edits", "status": "completed"}

def scheduled_tasks():
    loggingFunc("scheduled tasks simulation.")
    return {"use_case": "scheduled_tasks", "status": "completed"}

def encrypted_traffic():
    loggingFunc("scheduled tasks simulation.")
    return {"use_case": "encrypted_traffic", "status": "completed"}

def traffic_non_standard_ports():
    loggingFunc("traffic_non_standard_ports simulation.")
    return {"use_case": "traffic_non_standard_ports", "status": "completed"}


# Execution Flow Functions
def useCaseChecker():
    logs = []
    for use_case, enabled in USE_CASES.items():
        if enabled:
            func = globals().get(use_case)  # Dynamically call the use case function
            if func:
                result = func()
                logs.append(result)
            else:
                loggingFunc(f"Use case function {use_case} not found.")
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
                    loggingFunc("Received stop signal. Initiating cleanup.")
                    cleanUp()
                    break
            else:
                print(f"Heartbeat failed: {response.status_code}")
            time.sleep(heartbeatRate)
    except Exception as e:
        loggingFunc(f"Error in heartbeat: {e}")


# Main Execution
if __name__ == "__main__":
    try:
        loggingFunc("Starting test virus execution.")
        
        # Step 1: Execute use cases and collect aggregated logs
        logs = useCaseChecker()
        loggingFunc(f"Aggregated logs: {logs}")

        # Step 2: Send aggregated logs to the API
        dataToSend(logs)

        # Step 3: Enter heartbeat monitoring
        heart_beat()

    except Exception as e:
        loggingFunc(f"Error in main execution: {e}")
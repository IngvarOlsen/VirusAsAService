import time
import requests
import logging

# Configurable Variables
API_KEY = "ec6299c92a1a774af43410895c4746669b497f5bf424122d4b0178501492cc58"  
USE_CASES = {
    'ransomware_simulation': True, 'dns_tunneling': True, 'net_recon': True, 'dll_side_loading': True, 'registry_edits': True, 'scheduled_tasks': True, 'encrypted_traffic': True, 'traffic_non_standard_ports': True
}
heartbeatRate = 1111  # in seconds

# Helper Functions
def loggingFunc(log_data):
    """
    Logs data locally to a file.

    :param log_data: The log message or data to be logged.
    """
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


# The rest of the usecases


# Execution Flow Functions
def useCaseChecker():
    """
    Executes use cases based on the USE_CASES configuration.
    """
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
    """
    Sends periodic heartbeat signals to the API.
    If the API responds with a stop signal, triggers cleanup.
    """
    try:
        while True:
            response = requests.post(
                "http://127.0.0.1:5000/api/heartbeat",
                json={"api_key": API_KEY},
            )
            if response.status_code == 200:
                if response.json().get("stop_signal"):
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
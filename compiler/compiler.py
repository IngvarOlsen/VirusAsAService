import requests
import os
import zipfile
from cx_Freeze import setup, Executable
import shutil
import subprocess

# API URLs and secrets
api_get_url = "http://127.0.0.1:5000/api/getpendingjob"
api_upload_url = "http://127.0.0.1:5000/api/uploadcompiledjob"
secret = "verySecretAuth"  # Authorization header for fetching pending jobs, would have to be made an actual key which would be shared on deploying the compiler
# Paths and filenames
template_path = "templateVirus.py"
build_dir = "build"
dist_dir = "dist"
compiled_zip_path = "compiled_test_virus.zip"

# Formats the incoming usecases, if its present in the data it will be equal true, and parsed for the placeholder value
def format_use_case_settings(use_case_settings):
    # Mapping of received settings to function-compatible names
    use_case_map = {
        "Ransomware Simulation": "ransomware_simulation",
        "DNS Tunneling": "dns_tunneling",
        "Net.exe Recon": "net_recon",
        "DLL Side Loading": "dll_side_loading",
        "Registry Edits": "registry_edits",
        "Scheduled Tasks": "scheduled_tasks",
        "Encrypted Traffic": "encrypted_traffic",
        "Traffic on none standard ports": "traffic_non_standard_ports"
    }
    # Generate the output 
    formatted_settings = {
        use_case_map[setting]: True
        for setting in use_case_settings
        if setting in use_case_map
    }
    # Add all other use cases as False if not in use_case_settings
    for key in use_case_map.values():
        if key not in formatted_settings:
            formatted_settings[key] = False
    return formatted_settings

# Fetch pending job from the server, gets returned once job at a time
def get_pending_job():
    response = requests.get(api_get_url, headers={"Authorization": secret})
    if response.status_code == 200:
        job_data = response.json()
        print(f"Received job: {job_data}")
        return job_data
    else:
        print(f"Error fetching job: {response.json().get('message')}")
        return None

# Modifies the template py testvirus and inserts the varibles for api_key, heartbeat_rate and use_cases
def create_test_virus(template_path, output_path, job_data):
    try:
        with open(template_path, 'r') as template_file:
            script_content = template_file.read()
        script_content = script_content.replace("PLACEHOLDER_API_KEY", job_data["virus_api"])
        script_content = script_content.replace("PLACEHOLDER_HEARTBEAT_RATE", str(job_data["heartbeat_rate"]))
        script_content = script_content.replace("PLACEHOLDER_USE_CASES", str(format_use_case_settings(job_data["use_case_settings"])))
        with open(output_path, 'w') as output_file:
            output_file.write(script_content)

        print(f"Test virus script created at {output_path}")
        return output_path
    except Exception as e:
        print(f"Error creating test virus script: {e}")
        return None

# Compile the test virus using cx_Freeze
def compile_test_virus(script_path):
    print("compile_test_virus")
    print(script_path)
    try:
        if os.path.exists(build_dir):
            shutil.rmtree(build_dir)
        if os.path.exists(dist_dir):
            shutil.rmtree(dist_dir)
        print("Seting up freeze")
        # Path to the temporary setup script
        setup_script = "setup_compile.py"
        # Create a temporary setup script for cx_Freeze
        with open(setup_script, "w") as file:
            file.write(f"""
from cx_Freeze import setup, Executable

setup(
name="test_virus",
version="1.0",
description="Test Virus",
executables=[Executable("{script_path}")]
)
""")
        print("Setup script created.")
        # Run the build process using the setup script
        subprocess.run(["compiler-venv/Scripts/python", setup_script, "build"], check=True)
        print("Compilation complete.")
        # Clean up the setup script after compilation
        os.remove(setup_script)
    except subprocess.CalledProcessError as e:
        print(f"Error during compilation: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

# Zip the compiled virus
def zip_compiled_virus(build_folder, zip_path):
    try:
        # Dynamically locate the actual folder inside the build directory
        for root, dirs, files in os.walk(build_folder):
            if dirs:  # Look for the first directory inside the build folder
                actual_output_folder = os.path.join(root, dirs[0])
                break
        else:
            raise FileNotFoundError("No compiled folder found in the build directory.")

        # Create the zip file
        with zipfile.ZipFile(zip_path, 'w') as zipf:
            for root, dirs, files in os.walk(actual_output_folder):
                for file in files:
                    file_path = os.path.join(root, file)
                    # Add files to the zip archive, preserving directory structure
                    zipf.write(file_path, os.path.relpath(file_path, actual_output_folder))
        
        print(f"Compiled virus zipped successfully at {zip_path}")
        return zip_path

    except Exception as e:
        print(f"Error zipping compiled virus: {e}")
        return None

# def zip_compiled_virus(zip_path):
#     try:
#         with zipfile.ZipFile(zip_path, 'w') as zipf:
#             for root, dirs, files in os.walk(dist_dir):
#                 for file in files:
#                     file_path = os.path.join(root, file)
#                     zipf.write(file_path, os.path.relpath(file_path, dist_dir))
#         print(f"Compiled virus zipped at {zip_path}")
#         return zip_path
#     except Exception as e:
#         print(f"Error zipping compiled virus: {e}")
#         return None

# Upload the compiled and zipped virus
def upload_compiled_virus(zip_path, job_id, api_key):
    print("upload_compiled_virus")
    try:
        with open(zip_path, 'rb') as file:
            response = requests.post(
                api_upload_url,
                headers={"Authorization": api_key},
                data={"job_id": job_id},
                files={"compiled_file": file}
            )
            if response.status_code == 200:
                print("Compiled file uploaded successfully")
                return True
            else:
                print(f"Error uploading file: {response.json().get('message')}")
                return False
    except Exception as e:
        print(f"Error uploading compiled virus: {e}")
        return False

# Cleans up the build files and zip file after the upload is complete
def clean_up_folders(build_folder, zip_path):
    try:
        # Removes the build directory
        if os.path.exists(build_folder):
            shutil.rmtree(build_folder)
            print(f"Cleaned up build folder: {build_folder}")
        # Removes the zip file
        if os.path.exists(zip_path):
            os.remove(zip_path)
            print(f"Cleaned up zip file: {zip_path}")
        # Removes the new test_virus.py which have been filled out with new variables in placeholder slots
        # if os.path.exists("test_virus.py"):
        #     os.remove("test_virus.py")
        #     print(f"Cleaned up zip file: test_virus.py")
    except Exception as e:
        print(f"Error during cleanup: {e}")

# Main execution flow
if __name__ == "__main__":
    # Step 1 Fetch a pending job
    job_data = get_pending_job()
    if not job_data:
        print("No jobs available.")
        exit()
    # Step 2 Create the test virus script
    output_script_path = "test_virus.py"
    script_path = create_test_virus(template_path, output_script_path, job_data)
    if not script_path:
        print("Failed to create test virus script.")
        exit()
    # Step 3 Compile the test virus
    compile_test_virus(script_path)
    # Step 4 Zip the compiled virus
    zip_path = zip_compiled_virus(build_dir, compiled_zip_path)
    #zip_path = zip_compiled_virus(compiled_zip_path)
    if not zip_path:
        print("Failed to zip the compiled virus.")
        exit()
    else:
        print(f"Compiled and zipped virus is ready at: {zip_path}")
    # Step 5 Upload the compiled virus, and cleans up the build project in case its successfull
    if upload_compiled_virus(zip_path, job_data["job_id"], job_data["virus_api"]):
        clean_up_folders(build_dir, compiled_zip_path)
    else:
        print("Could not upload the zip file")



### Start base of testing ###


# def getJobs():
#     response = requests.get(apiGetUrl, headers={"Authorization": secret})

#     if response.status_code == 200:
#         jobData = response.json()
#         print(f"Received job: {jobData}")
#         return jobData
#     else:
#         print(f"Error: {response.json().get('message')}")

# def uploadFile():
#     with open(compiledZipPath, 'rb') as file:
#         response = requests.post(
#         apiUploadUrl,
#         headers={"Authorization": testApi},
#         data={"job_id": 3},
#         files={"compiled_file": file}
#     )
#     if response.status_code == 200:
#         print("Compiled file uploaded successfully")
#         print(response)
#     else:
#         print(f"Error: {response.json().get('message')}")
    
# getJobs()
# print(uploadFile())
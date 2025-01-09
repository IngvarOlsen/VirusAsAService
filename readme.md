# VirusAsAService

This Bachelor project demonstrates a proof-of-concept “Virus-as-a-Service” platform.
The goal is it to be service and tool for making test-virusses, to find out if a clients ID, IPS or endpointprotection systems are able to detect the activity from the test-virus.

The use-cases activities right now is: ransomeware, net.exe reconnaissance, schedule task manipulation and registry manipulation. 

It consists of two main components:

1. A **Flask** Web application, hosted on Linux or any environment supporting Python 3.
2. A **Windows** Compiler environment which generates the test-virus using `ex_freeze`.

Below are the steps to get both environments up and running.


## 1. Flask App Environment

### Prerequisites
- Python installed
- Git installed

### Clone the Repository

Clone down the project in the current folder
```
git clone https://github.com/IngvarOlsen/VirusAsAService.git .
```

Make venv
```
python3 -m venv flask-venv 
```

Activate venv
```
flask-venv\Scripts\activate.ps1 (Windows)
or
source flask-venv/bin/activate (Linux)
```

Install requirements
```
pip install -r requirements.txt
```

Run the app, with the optional --debug for more info
```
flask --debug run
```

For hosting dev
```
flask run --host=0.0.0.0 --port=80 (Our project just gets free SSL encryption with CloudFlare proxy)
```

For Browsers like Brave, disable shields as it will interfere with cookies and login session


## 2. Compiler enviroment 

```
cd compiler
python3 -m venv compiler-venv 
pip install --upgrade cx_Freeze
pip install requests
pip install cryptography
pip install scapy
```
Once a compiling job is ready run: 
```
python3 compiler.py
```
Note that it will be made into a compiling loop in future updates

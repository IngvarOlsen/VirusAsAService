#from web import create_app, create_database
from web import create_app
from threading import Thread
from dns_server import run_dns_server
# from sanic import Sanic
# from sanic.response import html
from flask import send_from_directory
import socketio
import os

# Starts the dns sever in the background and closes with flask with daemon=True
def start_dns_in_background():
    try:
        print("Trying to start DNS server...")
        t = Thread(target=run_dns_server, daemon=True)
        t.start()
    except Exception as e:
        print(e)

start_dns_in_background()
app = create_app()

# Does not get run by "flask run"
if __name__ == '__main__':

    app.run(host="0.0.0.0", port=5000, debug=True)
    #app.run(host="0.0.0.0", port=5000, debug=True, ssl_context=('cert.pem', 'certpriv_key.pem')) # For SSL
#from web import create_app, create_database
from web import create_app
# from sanic import Sanic
# from sanic.response import html
from flask import send_from_directory
import socketio
import os

app = create_app()

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
    #app.run(host="0.0.0.0", port=5000, debug=True, ssl_context=('cert.pem', 'certpriv_key.pem')) # For SSL
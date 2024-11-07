from flask import request, jsonify
from app import app

@app.route('/')
def home():
    return "Hello, Flask!"

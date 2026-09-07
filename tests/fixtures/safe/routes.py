from flask import Flask, request
from repository import find_users

app = Flask(__name__)


@app.get('/users')
def users():
    term = request.args.get('name', '')
    return {'users': find_users(term)}

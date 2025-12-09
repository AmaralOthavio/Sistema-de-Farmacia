from flask import Flask
import fdb
from flask_cors import CORS
from flask_jwt_extended import JWTManager

app = Flask(__name__)
CORS(app, origins=["*"])
app.config.from_pyfile('config.py')
password = app.config['DB_PASSWORD']
app.config['JWT_SECRET_KEY'] = password

jwt = JWTManager(app)

host = app.config['DB_HOST']
database = app.config['DB_NAME']
user = app.config['DB_USER']

debug = app.config['DEBUG']

try:
    con = fdb.connect(host=host, database=database, user=user, password=password)
    print(f"Conexão estabelecida com sucesso")
except Exception as e:
    print(f"Erro de conexão com o banco: {e}")

from view import *

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=debug)

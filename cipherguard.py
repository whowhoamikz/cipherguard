from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin
from flask_login import LoginManager, login_user, login_required, logout_user
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import base64
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = "TuClaveSecreta"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
db = SQLAlchemy(app)

# Definición de modelos de base de datos para Flask-Security
roles_users = db.Table(
    'roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
)

class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    roles = db.relationship(
        'Role', secondary=roles_users,
        backref=db.backref('users', lazy='dynamic')
    )

user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def secure_key_derivation(password, salt):
    return PBKDF2(password.encode(), salt, dkLen=32, count=100000)

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
@login_required
def encrypt():
    message = request.form['message']
    password = request.form['password']

    salt = get_random_bytes(16)
    key = secure_key_derivation(password, salt)
    
    cipher = AES.new(key, AES.MODE_CFB)
    ciphertext = cipher.encrypt(message.encode())

    encrypted_message = base64.b64encode(ciphertext).decode()
    encrypted_metadata = base64.b64encode(salt).decode()

    return jsonify({'encrypted_message': encrypted_message, 'encrypted_metadata': encrypted_metadata})

@app.route('/decrypt', methods=['POST'])
@login_required
def decrypt():
    encrypted_message = request.form['encrypted_message']
    encrypted_metadata = request.form['encrypted_metadata']
    password = request.form['password']

    salt = base64.b64decode(encrypted_metadata)
    key = secure_key_derivation(password, salt)
    
    ciphertext = base64.b64decode(encrypted_message)
    cipher = AES.new(key, AES.MODE_CFB)
    
    try:
        decrypted_message = cipher.decrypt(ciphertext).decode()
        return jsonify({'decrypted_message': decrypted_message})
    except Exception as e:
        return jsonify({'error': 'Error al desencriptar el mensaje.'}), 400

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)

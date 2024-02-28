from flask import Flask, render_template, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import random
import string

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///passwords.db'
app.secret_key = 'your_secret_key'
key = Fernet.generate_key()
cipher_suite = Fernet(key)

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.LargeBinary, nullable=False)

class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    website = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(50), nullable=False)
    password = db.Column(db.LargeBinary, nullable=False)
    additional_info = db.Column(db.Text)

def encrypt_data(data):
    return cipher_suite.encrypt(data.encode())

def decrypt_data(encrypted_data):
    return cipher_suite.decrypt(encrypted_data).decode()

@app.route('/')
def index():
    if 'user_id' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)
        passwords = Password.query.filter_by(user_id=user_id).all()
        return render_template('index.html', username=user.username, passwords=passwords)
    else:
        return redirect('/login')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        encrypted_password = encrypt_data(hashed_password)
        new_user = User(username=username, password=encrypted_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/login')
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(decrypt_data(user.password), password):
            session['user_id'] = user.id
            return redirect('/')
        else:
            return 'Invalid username or password.'
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect('/')

@app.route('/generate_password', methods=['POST'])
def generate_password():
    length = int(request.form['length'])
    characters = string.ascii_letters + string.digits + string.punctuation
    generated_password = ''.join(random.choice(characters) for _ in range(length))
    return generated_password

@app.route('/add_password', methods=['POST'])
def add_password():
    user_id = session['user_id']
    website = request.form['website']
    username = request.form['username']
    password = request.form['password']
    additional_info = request.form['additional_info']
    encrypted_password = encrypt_data(password)
    new_password = Password(user_id=user_id, website=website, username=username, password=encrypted_password, additional_info=additional_info)
    db.session.add(new_password)
    db.session.commit()
    return redirect('/')

@app.route('/edit_password/<int:id>', methods=['POST'])
def edit_password(id):
    password = Password.query.get(id)
    password.website = request.form['website']
    password.username = request.form['username']
    password.password = encrypt_data(request.form['password'])
    password.additional_info = request.form['additional_info']
    db.session.commit()
    return redirect('/')

@app.route('/delete_password/<int:id>')
def delete_password(id):
    password = Password.query.get(id)
    db.session.delete(password)
    db.session.commit()
    return redirect('/')

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)

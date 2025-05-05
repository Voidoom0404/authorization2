from flask import Flask, render_template, redirect, url_for, request, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
import requests
import logging

app = Flask(__name__)
app.config['SECRET_KEY'] = 'f6d1777bf6d1777bf6d1777bddf5e1ca6eff6d1f6d1777b9ec9070ada9e0999ebac8a8a'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['VK_CLIENT_ID'] = '53525781'
app.config['VK_CLIENT_SECRET'] = 'EioeDbbhJKqrk4Fs5xIi'
app.config['VK_REDIRECT_URI'] = 'http://127.0.0.1:5000/callback'

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
logging.basicConfig(filename='auth.log', level=logging.INFO)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), default='user')  
with app.app_context():
    db.create_all()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash('Регистрация прошла успешно!')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Успешный вход!')
            return redirect(url_for('profile'))
        else:
            flash('Неверные имя пользователя или пароль.')
    return render_template('login.html')

@app.route('/callback')
def callback():
    code = request.args.get('code')
    if not code:
        return 'Authorization failed', 400

    response = requests.get(
        'https://oauth.vk.com/access_token',
        params={
            'client_id': app.config['VK_CLIENT_ID'],
            'client_secret': app.config['VK_CLIENT_SECRET'],
            'redirect_uri': app.config['VK_REDIRECT_URI'],
            'code': code
        }
    )
    data = response.json()
    if 'access_token' in data:
        access_token = data['access_token']
        user_id = data['user_id']
        session['access_token'] = access_token
        session['user_id'] = user_id
        return redirect(url_for('profile'))
    return 'Authorization failed', 400

@app.route('/profile')
def profile():
    if 'access_token' in session and 'user_id' in session:
        user_id = session['user_id']
        return f'User ID: {user_id}'
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
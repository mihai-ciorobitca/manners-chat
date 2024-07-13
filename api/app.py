from flask import Flask, render_template, request, session, redirect
from supabase import create_client
from werkzeug.security import check_password_hash, generate_password_hash
from dotenv import load_dotenv
from os import getenv
from requests import post

load_dotenv()

app = Flask(__name__)

app.secret_key ='secret_key'

supabase_url = getenv('SUPABASE_URL')
supabase_key = getenv('SUPABASE_KEY')
recaptcha_secret = getenv('RECAPTCHA_SECRET')
supabase_client = create_client(supabase_url, supabase_key)

@app.route('/')
def home():
    if 'username' in session:
        groups = supabase_client.table("messages").select('*').execute().data
        messages = supabase_client.table("messages").select('*').execute().data
        return render_template('index.html', username=session["username"], messages=messages, groups=groups)
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = supabase_client.table('users').select('username,password').eq('username', username).execute().data
        if len(user) > 0:
            if check_password_hash(user[0]['password'], password):
                session['username'] = username
                return redirect('/')
            return render_template('login.html', errorMsg="Invalid password")
        return render_template('login.html', errorMsg="User not found")
    return render_template('login.html', errorMsg="")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        recaptcha_response = request.form['g-recaptcha-response']
        captcha_data = {
            'secret': recaptcha_secret,
            'response': recaptcha_response
        }
        captcha_verify = post('https://www.google.com/recaptcha/api/siteverify', data=captcha_data)
        captcha_response = captcha_verify.json()
        if not captcha_response['success']:
            return render_template('register.html', errorMsg="reCAPTCHA verification failed. Please try again.")
        user = supabase_client.table('users').select("username").eq('username', username).execute().data
        if len(user) > 0:
            return render_template('register.html', errorMsg="Username already exists")

        password = request.form['password']
        supabase_client.table('users').insert({"username": username, "password": generate_password_hash(password)}).execute()
        return redirect('/login')   
    return render_template('register.html', errorMsg="")

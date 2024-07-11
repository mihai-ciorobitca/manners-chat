from flask import Flask, render_template, request, session, redirect
from supabase import create_client

app = Flask(__name__)

app.secret_key ='secret_key'

supabase_url = "https://sbvcrvdxmvloiowjjmay.supabase.co"
supabase_key = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InNidmNydmR4bXZsb2lvd2pqbWF5Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTcyMDY0MTA5MCwiZXhwIjoyMDM2MjE3MDkwfQ.b4InyfVM_vLFuKnCTiu-f8e0LGkR_G8RGHQKnVxlwF4"
supabase_client = create_client(supabase_url, supabase_key)

@app.route('/')
def home():
    if 'username' in session:
        return render_template('index.html')
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = supabase_client.table('users').select('username,password').eq('username', username).eq('password', password).execute()
        if user[0]:
            session['username'] = username
            return redirect('/')
    return render_template('login.html')

@app.route('/register')
def register():
    return render_template('register.html')


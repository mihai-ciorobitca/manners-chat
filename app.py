from flask import Flask, render_template, request, session, redirect
from supabase import create_client
from werkzeug.security import check_password_hash, generate_password_hash
from dotenv import load_dotenv
from os import getenv
from requests import post
from flask_socketio import SocketIO, emit, join_room, leave_room

load_dotenv()

app = Flask(__name__)
app.secret_key = 'secret_key'

supabase_url = getenv('SUPABASE_URL')
supabase_key = getenv('SUPABASE_KEY')
recaptcha_secret = getenv('RECAPTCHA_SECRET')
supabase_client = create_client(supabase_url, supabase_key)

socketio = SocketIO(app, cors_allowed_origins="*")

@app.route('/')
def home():
    if 'username' in session:
        username = session['username']
        groups_query = supabase_client.from_('user_groups').select('groupname').eq('username', username)
        groups_response = groups_query.execute()
        groups = [group['groupname'] for group in groups_response.data] if groups_response.data else []
        
        return render_template('index.html', username=username, groups=groups)
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
                session['clearLocalStorage'] = True
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

@socketio.on('send_message')
def send_message(data):
    username = session.get('username')
    if username:
        text = data['text']
        groupname = data['groupname']
        try:
            supabase_client.table('messages').insert({
                'username': username,
                'text': text,
                'groupname': groupname,
                'date': data['date']
            }).execute()
            emit('receive_message', data, groupname=groupname, broadcast=True)
        except Exception as e:
            print(f"Error: {e}")

@socketio.on('get_messages')
def get_messages(data):
    groupname = data['groupname']
    response = supabase_client.table('messages').select('*').eq('groupname', groupname).order('date').execute()
    messages = response.data if response.data else []
    emit('message_list', messages)

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    session.pop('clearLocalStorage', None)
    return redirect('/login')

if __name__ == '__main__':
    socketio.run(app, debug=True)
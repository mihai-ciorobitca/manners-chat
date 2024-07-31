from flask import Flask, render_template, request, session, redirect
from supabase import create_client
from werkzeug.security import check_password_hash, generate_password_hash
from dotenv import load_dotenv
from os import getenv
from requests import post
from flask_session import Session
from flask_socketio import SocketIO, emit
import pyotp

load_dotenv()

app = Flask(__name__)
app.secret_key = 'secret_key'
Session(app)
supabase_url = getenv('SUPABASE_URL')
supabase_key = getenv('SUPABASE_KEY')
recaptcha_secret = getenv('RECAPTCHA_SECRET')
supabase_client = create_client(supabase_url, supabase_key)

socketio = SocketIO(app, cors_allowed_origins="*", manage_session=False)


@app.route('/')
def home():
    if 'username' in session:
        username = session['username']
        groupname = session.get("groupname", "No Group Open")
        groupmessage = session.get("groupmessage", "Hello Group")
        groups_query = supabase_client.from_(
            'user_groups').select('groupname,sharelink')
        if session["username"] != 'admin':
            groups = groups_query.eq(
                'username', username).execute().data
        else:
            groups = supabase_client.from_('groups').select(
                'groupname,sharelink').execute().data
        print(groups)
        return render_template('index.html', username=username, groups=groups, groupname=groupname, groupmessage=groupmessage)
    return redirect('/login')

@app.route("/groups/<uuid:sharelink>")
def join_group(sharelink):
    if 'username' in session:
        username = session["username"]
        if username == 'admin':
            return redirect("/")
        response = supabase_client.table("groups").select("groupname").eq("sharelink", str(sharelink)).execute().data
        if len(response) == 0:
            return redirect("/")
        groupname = response[0]["groupname"]
        supabase_client.table("user_groups").insert({"groupname": groupname, "username": username,"sharelink": sharelink}).execute()
    return redirect("/login")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = supabase_client.table('users').select(
            'username,password').eq('username', username).execute().data
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
        captcha_verify = post(
            'https://www.google.com/recaptcha/api/siteverify', data=captcha_data)
        captcha_response = captcha_verify.json()
        if not captcha_response['success']:
            return render_template('register.html', errorMsg="reCAPTCHA verification failed. Please try again.")
        user = supabase_client.table('users').select(
            "username").eq('username', username).execute().data
        if len(user) > 0:
            return render_template('register.html', errorMsg="Username already exists")
        password = request.form['password']
        email = request.form['email']
        supabase_client.table('users').insert(
            {"username": username, "password": generate_password_hash(password), "email": email, "otp": pyotp.random_base32()}).execute()
        return redirect('/login')
    return render_template('register.html', errorMsg="")


@app.route("/add-group", methods=["POST"])
def add_group():
    groupname = request.form["groupname"]
    supabase_client.table("groups").insert({"groupname": groupname}).execute()
    return redirect("/")


@socketio.on('send_message')
def send_message(data):
    username = session.get('username')
    if username:
        text = data['text']
        groupname = session['groupname']
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
    session["groupname"] = groupname
    groupmessage = supabase_client.from_("groups").select(
        "groupmessage").eq("groupname", groupname).execute().data
    if len(groupmessage) > 0:
        groupmessage = groupmessage[0]["groupmessage"]
    else:
        groupmessage = ""
    session["groupmessage"] = groupmessage
    response = supabase_client.table('messages').select(
        '*').eq('groupname', groupname).order('date').execute()
    messages = response.data if response.data else []
    emit('message_list', messages)


@app.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    return redirect('/login')


@app.route('/update-message', methods=['POST'])
def update_message():
    groupname = request.form["groupname"]
    groupmessage = request.form["groupmessage"]
    supabase_client.table("groups").update(
        {"groupmessage": groupmessage}).eq("groupname", groupname).execute()
    session["groupmessage"] = groupmessage
    return redirect("/")


@app.route("/reset", methods=["POST", "GET"])
def reset():
    if request.method == "POST":
        otp = request.form["otp"]
        users = supabase_client.table('users').select(
            "*").eq('otp', otp).execute().data
        if len(users) > 0:
            user = users[0]
            print(user)
            secret = request.form["secret"]
            totp = pyotp.TOTP(user['otp'])
            if totp.verify(secret):
                new_password = request.form["new-password"]
                supabase_client.table("users").update({"password": generate_password_hash(
                    new_password)}).eq("username", user["username"]).execute()
                return redirect("/login")
            return render_template("reset.html", errorMsg="Wrong secret")
        return render_template("reset.html", errorMsg="OPT not found")
    return render_template("reset.html", errorMsg="")

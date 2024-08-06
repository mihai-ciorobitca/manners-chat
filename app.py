from flask import Flask, render_template, request, session, redirect
from supabase import create_client
from werkzeug.security import check_password_hash, generate_password_hash
from dotenv import load_dotenv
from os import getenv
from requests import post
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_session import Session
import pyotp
from pymongo import MongoClient

load_dotenv()

app = Flask(__name__)
app.secret_key = 'secret_key'
supabase_url = getenv('SUPABASE_URL')
supabase_key = getenv('SUPABASE_KEY')
recaptcha_secret = getenv('RECAPTCHA_SECRET')
supabase_client = create_client(supabase_url, supabase_key)

app.config['SESSION_TYPE'] = 'mongodb'
app.config['SESSION_MONGODB'] = MongoClient(getenv('MONGO_URI'))
app.config['SESSION_MONGODB_DB'] = 'database'
app.config['SESSION_MONGODB_COLLECT'] = 'sessions'

Session(app)

socketio = SocketIO(app, cors_allowed_origins="*", manage_session=False)


@app.route('/')
def home():
    if 'username' in session:
        username = session['username']
        response = supabase_client.from_("users").select(
            "otp").eq('username', username).execute().data
        otp = ""
        if len(response) != 0:
            otp = response[0]["otp"]
        groupname = session.get("groupname", "No Group Open")
        response = supabase_client.from_("groups").select(
            "groupmessage").eq("groupname", groupname).execute().data
        groupmessage = "Hello everyone!"
        if len(response) != 0:
            groupmessage = response[0]["groupmessage"]
        session["groupmessage"] = groupmessage
        groups_query = supabase_client.from_(
            'user_groups').select('groupname,sharelink')
        if session["username"] != 'admin':
            groups = groups_query.eq('username', username).execute().data
        else:
            groups = supabase_client.from_('groups').select(
                'groupname,sharelink').execute().data
        return render_template('index.html',
                               username=username, groups=groups,
                               groupname=groupname,
                               otp=otp
                               )
    return redirect('/login')


@app.route("/groups/<uuid:sharelink>")
def join_group(sharelink):
    if 'username' in session:
        username = session["username"]
        if username == 'admin':
            return redirect("/")
        response = supabase_client.table("groups").select(
            "groupname").eq("sharelink", str(sharelink)).execute().data
        if len(response) == 0:
            return redirect("/")
        groupname = response[0]["groupname"]
        supabase_client.table("user_groups").insert(
            {"groupname": groupname, "username": username, "sharelink": str(sharelink)}).execute()
        return redirect("/")
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


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect('/login')


@socketio.on('send_message')
def send_message(data):
    username = session.get('username')
    text = data['text']
    groupname = session['groupname']
    supabase_client.table('messages').insert({
        'username': username,
        'text': text,
        'groupname': groupname,
        'date': data['date']
    }).execute()
    emit('receive_message', data, to=groupname)


@socketio.on('get_messages')
def get_messages(data):
    old_groupname = session.get("groupname", None)
    if old_groupname:
        leave_room(old_groupname)
    groupname = data['groupname']
    join_room(groupname)
    session["groupname"] = groupname
    groupmessage = supabase_client.from_("groups").select(
        "groupmessage").eq("groupname", groupname).execute().data
    if len(groupmessage) > 0:
        groupmessage = groupmessage[0]["groupmessage"]
    else:
        groupmessage = ""
    response = supabase_client.table('messages').select(
        '*').eq('groupname', groupname).order('date').execute()
    messages = response.data if response.data else []
    emit('message_list', {"messages": messages,
         "groupmessage": groupmessage}, to=groupname)


@socketio.on('update_message')
def update_message(data):
    groupname = data['groupname']
    groupmessage = data['groupmessage']
    print("Updating in group " + groupname)
    supabase_client.table("groups").update(
        {"groupmessage": groupmessage}).eq("groupname", groupname).execute()
    session["groupmessage"] = groupmessage
    emit('message_update', {'groupname': groupname,
         'groupmessage': groupmessage}, to=groupname)


@app.route("/reset", methods=["POST", "GET"])
def reset():
    if request.method == "POST":
        username = request.form["username"]
        users = supabase_client.table('users').select(
            "*").eq('username', username).execute().data
        if len(users) > 0:
            user = users[0]
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


@app.route('/delete-group', methods=['POST'])
def delete_group():
    groupname = request.form['groupname']
    supabase_client.table('groups').delete().eq(
        'groupname', groupname).execute()
    session.pop("groupname")
    return redirect('/')


@socketio.on('update_group')
def update_group(data):
    new_groupname = data['new_groupname']
    groupname = data['groupname']
    supabase_client.table('groups').update(
        {"groupname": new_groupname}).eq('groupname', groupname).execute()
    session["groupname"] = new_groupname
    emit('group_name_updated', {'new_groupname': new_groupname})

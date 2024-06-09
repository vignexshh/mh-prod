from flask import Flask, render_template, request, session, jsonify, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
import bcrypt
from flask import flash
import pandas as pd
from wtforms import IntegerField, SelectField,SelectMultipleField,BooleanField
from wtforms.validators import InputRequired
from wtforms import StringField, PasswordField, SelectField, SubmitField
from wtforms.validators import InputRequired, DataRequired, Length
from flask_mail import Mail, Message
import pandas as pd
import bcrypt
import json
import hashlib
import datetime
import logging
import firebase_admin
from firebase_admin import credentials, db
import random
import math

# Initialize Flask app
app = Flask(__name__)
app.secret_key = "778031a659c117f6ab82986676e24271"

#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///MediSearch.db'
#db = SQLAlchemy(app)

#pandas
#-------------------------------------------------
#Telangana MBBS & BDS
data_frame=pd.read_csv('../Tel & Ap Data/medicine_parsed-2.csv')
data_frame['EWS']=data_frame['EWS'].fillna(value="NO")
data_frame_p2=pd.read_csv('../Tel & Ap Data/p2.csv')
data_frame_p3=pd.read_csv('../Tel & Ap Data/p3.csv')
data_frame_p4=pd.read_csv('../Tel & Ap Data/41.csv')
tel_dbs=pd.read_csv('../Tel & Ap Data/test3.csv')
tel_merit_list=pd.read_csv('../Tel & Ap Data/600.csv')

#Telangana Aush 
tel_ayush = pd.read_csv('../Tel & Ap Data/TelanganaAyushData.csv')
tel_merit_ayush=pd.read_csv('../Tel & Ap Data/21.csv')

#Andhra MBBS & BDS
andhra_mbbs_list = pd.read_csv('../Tel & Ap Data/Ap_sort_Mbbs.csv')
andhra_bds_list = pd.read_csv('../Tel & Ap Data/completeApBDS.csv')
andhra_merit_list = pd.read_csv('../Tel & Ap Data/AndhraMerit.csv')

#Andhra Aush
andhra_aush_list = pd.read_csv('../Tel & Ap Data/test2.csv')
andhra_aush_merit_list = pd.read_csv('../Tel & Ap Data/meritApAUSH.csv')

#All India
all_india_list = pd.read_csv('../Tel & Ap Data/allIndia.csv')
#tel management 
tel_management = pd.read_csv('../Tel & Ap Data/telanaganamanagement.csv')
#AP_management 
ap_management = pd.read_csv('../Tel & Ap Data/Ap_mng.csv')
#Flask Mail Configuration
#------------------------------------------
# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'eligetivignesh@gmail.com'
app.config['MAIL_PASSWORD'] = 'xvvs fbud kiir ihfd'
app.config['MAIL_DEFAULT_SENDER'] = app.config['MAIL_USERNAME']
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)

# Initialize Firebase Admin SDK
cred = credentials.Certificate("../mediksearch-firebase-adminsdk-xuwjd-c26d2b8715.json")
firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://medi-rakesh-503bc-default-rtdb.firebaseio.com/'
})

# Firebase database reference
ref = db.reference()

# Load CSV data
data_frame = pd.read_csv('../Tel & Ap Data/medicine_parsed-2.csv')
data_frame['EWS'] = data_frame['EWS'].fillna(value="NO")
data_frame_p2 = pd.read_csv('../Tel & Ap Data/p2.csv')
data_frame_p3 = pd.read_csv('../Tel & Ap Data/p3.csv')
data_frame_p4 = pd.read_csv('../Tel & Ap Data/41.csv')
tel_dbs = pd.read_csv('../Tel & Ap Data/test3.csv')
tel_merit_list = pd.read_csv('../Tel & Ap Data/600.csv')

tel_ayush = pd.read_csv('../Tel & Ap Data/TelanganaAyushData.csv')
tel_merit_ayush = pd.read_csv('../Tel & Ap Data/21.csv')

andhra_mbbs_list = pd.read_csv('../Tel & Ap Data/Ap_sort_Mbbs.csv')
andhra_bds_list = pd.read_csv('../Tel & Ap Data/completeApBDS.csv')
andhra_merit_list = pd.read_csv('../Tel & Ap Data/AndhraMerit.csv')

andhra_aush_list = pd.read_csv('../Tel & Ap Data/test2.csv')
andhra_aush_merit_list = pd.read_csv('../Tel & Ap Data/meritApAUSH.csv')

all_india_list = pd.read_csv('../Tel & Ap Data/allIndia.csv')

# Database Models
class AcceptedUsers:
    def __init__(self, username, email, password, transactionId, phone_number):
        self.username = username
        self.email = email
        self.password = password
        self.transactionId = transactionId
        self.phone_number = phone_number

    def save_to_firebase(self):
        accepted_users_ref = ref.child("accepted_users").child(self.username)
        accepted_users_ref.set({
            "email": self.email,
            "password": self.password,
            "transactionId": self.transactionId,
            "phone_number": self.phone_number
        })


class RequestedUsers:
    def __init__(self, username, email, password, transactionId, phone_number, action="pending"):
        self.username = username
        self.email = email
        self.password = password
        self.transactionId = transactionId
        self.action = action
        self.phone_number = phone_number

    def save_to_firebase(self):
        requested_users_ref = ref.child("requested_users").child(self.username)
        requested_users_ref.set({
            "email": self.email,
            "password": self.password,
            "transactionId": self.transactionId,
            "phone_number": self.phone_number,
            "action": self.action
        })


class UserDetails:
    def __init__(self, username, hashed_password, salt):
        self.username = username
        self.hashed_password = hashed_password
        self.salt = salt

    def save_to_firebase(self):
        user_details_ref = ref.child("user_details").child(self.username)
        user_details_ref.set({
            "hashed_password": self.hashed_password,
            "salt": self.salt
        })
class NotificationForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=100)])
    link = StringField('Link', validators=[DataRequired(), Length(max=200)])
    visible = BooleanField('Visible')
    submit = SubmitField('Post Notification')



# Password Hashing
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8'), salt.decode('utf-8')


def store_user(username, password):
    hashed_password, salt = hash_password(password)
    user_ref = db.reference("user_details").child(username)
    new_user = {
        "hashed_password": hashed_password,
        "salt": salt
    }
    user_ref.set(new_user)


def verify_password(username, password):
    try:
        user = db.reference('user_details').child(username)
        user = user.get()
        salt = user['salt'].encode('utf-8')
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        hashed_password = hashed_password.decode('utf-8')
        return hashed_password == user['hashed_password']
    except Exception as e:
        print("Verify Password Error: ", str(e))
        return False


# Generate OTP
def generateOTP():
    digits = "0123456789"
    OTP = ""
    for i in range(4):
        OTP += digits[math.floor(random.random() * 10)]
    return OTP


# Read JSON File
def read_config_from_json(file_path):
    with open(file_path, 'r') as file:
        config = json.load(file)
    return config


# Forms
class UserDashboardForm(FlaskForm):
    config = read_config_from_json('../JSON/telanganaUser.json')

    scheme = SelectField('Scheme', choices=[(s, s) for s in config['schemes']], validators=[InputRequired()])
    phase = SelectField('Phases', choices=[(p, p) for p in config['phases']], validators=[InputRequired()])
    caste = SelectField('Caste', choices=[(c, c) for c in config['castes']], validators=[InputRequired()])
    ews = SelectField('EWS', choices=[(e, e) for e in config['ews_options']])
    locality = SelectField('Locality', choices=[(l, l) for l in config['localities']], validators=[InputRequired()])
    gender = SelectField('Gender', choices=[(g, g) for g in config['gender_options']], validators=[InputRequired()])
    colleges = SelectField('Colleges', choices=[(col, col) for col in config['colleges']])
    submit = SubmitField('Submit')

class TelanaganaManagementForm(FlaskForm):
    config = read_config_from_json('../JSON/telmgt.json')
    phase=SelectField('Phases',choices=[(p,p) for p in config['phases']],validators=[InputRequired()])
    category=SelectField('Category',choices=[(c,c) for c in config['category']],validators=[InputRequired()])
    locality = SelectField('Locality', choices=[(l, l) for l in config['localities']], validators=[InputRequired()])
    colleges = SelectField('Colleges', choices=[(col, col) for col in config['colleges']])
    submit = SubmitField('Submit')

class AndhraManagement(FlaskForm):
    config = read_config_from_json('../JSON/ApmngUser.json')
    phase = SelectField('Phases',choices=[(p,p) for p in config['phases']],validators=[InputRequired()])
    category= SelectField('Category',choices=[(c,c) for c in config['category']],validators=[InputRequired()])
    locality = SelectField('Locality',choices=[(l,l) for l in config['localities']],validators=[InputRequired()])
    colleges = SelectField('Colleges',choices=[(col,col) for col in config['colleges']])
    submit= SubmitField('Submit')

class AndhraUserDashboardForm(FlaskForm):
    config = read_config_from_json('../JSON/andhraUser.json')

    scheme = SelectField('Scheme', choices=[(s, s) for s in config['schemes']], validators=[InputRequired()])
    phase = SelectField('Phases', choices=[(p, p) for p in config['phases']], validators=[InputRequired()])
    caste = SelectField('Caste', choices=[(c, c) for c in config['castes']], validators=[InputRequired()])
    ews = SelectField('EWS', choices=[(e, e) for e in config['ews_options']])
    locality = SelectField('Locality', choices=[(l, l) for l in config['localities']], validators=[InputRequired()])
    gender = SelectField('Gender', choices=[(g, g) for g in config['gender_options']], validators=[InputRequired()])
    colleges = SelectField('Colleges', choices=[(col, col) for col in config['colleges']])
    submit = SubmitField('Submit')


class AllIndiaForm(FlaskForm):
    config = read_config_from_json('../JSON/allIndia.json')
    scheme = SelectField('Scheme', choices=[(s, s) for s in config['Scheme']], validators=[InputRequired()])
    quota = SelectField('Quota', choices=[(s, s) for s in config['Allocated Quota']], validators=[InputRequired()])
    phase = SelectField('Phase', choices=[(p, p) for p in config['Phase']], validators=[InputRequired()])
    caste = SelectField('Caste', choices=[(e, e) for e in config['Candidate Category']], validators=[InputRequired()])
    colleges = SelectField('Colleges', choices=[(l, l) for l in config['Allocated Institute']], validators=[InputRequired()])
    submit = SubmitField('Submit')


class AdminLoginForm(FlaskForm):
    username = StringField('Username')
    password = PasswordField('Password')
    submit = SubmitField('Login')


class UserLoginForm(FlaskForm):
    username = StringField('Username')
    password = PasswordField('Password')
    submit = SubmitField('Login')


class SignupForm(FlaskForm):
    email = StringField('Email')
    username = StringField('Username')
    password = PasswordField('Password')
    transactionId = StringField('transactionId')
    phone_number = StringField('Phone Number', validators=[DataRequired(), Length(min=10, max=15)])
    submit = SubmitField('SignUp')


class ForgotForm(FlaskForm):
    username = StringField('username')
    otp = StringField('otp')
    submit = SubmitField('Submit')


class ResetForm(FlaskForm):
    newPassword = PasswordField('New Password')
    conformPassword = PasswordField('Conform Password')
    submit = SubmitField('Submit')


@app.route('/', methods=['GET', 'POST'])
def home():
    form = UserLoginForm()
    return render_template('user_login.html', form=form)


@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    form = AdminLoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Hash the incoming password
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        admin_username = 'admin'
        admin_password = hashlib.sha256('admin123'.encode()).hexdigest()  # Store this hash securely

        if username == admin_username and hashed_password == admin_password:
            session['logged_in'] = True
            flash('Login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('admin_login.html', form=form)


@app.route('/user_login', methods=['GET', 'POST'])
def user_login():
    try:
        form = UserLoginForm()
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data

            # Check if the user exists in Firebase

            user_ref = db.reference("user_details").child(username)
            user_data = user_ref.get()

            if user_data:
                if verify_password(username, password):
                    # Check if the user is in RequestedUsers
                    requested_user_ref = db.reference("requested_users").child(username)
                    requested_user_data = requested_user_ref.get()

                    if requested_user_data:
                        flash('User not yet accepted', 'danger')
                        return home()

                    # Check if the user is in AcceptedUsers
                    accepted_user_ref = db.reference("accepted_users").child(username)
                    accepted_user_data = accepted_user_ref.get()

                    if accepted_user_data:
                        # Clear all flashed messages
                        session.pop('_flashes', None)

                        session['username'] = username
                        return render_template('page2.html', username=username)
                    else:
                        flash('Invalid username and password', 'danger')
                        return home()
                else:
                    flash('Invalid username and password', 'danger')
                    return home()
            else:
                flash('User not registered', 'danger')
                return home()

        return render_template('user_login.html', form=form)

    except Exception as e:
        return jsonify({"message": "User login error: " + str(e)}), 500


@app.route('/register', methods=['GET', 'POST'])
def register():
    try:
        form = SignupForm()
        if form.validate_on_submit():
            username = form.username.data
            email = form.email.data
            password = form.password.data
            transactionId = form.transactionId.data
            phone_number = form.phone_number.data
            # Check if the username already exists in Firebase
            user_ref = db.reference("user_details").child(username)
            if user_ref.get():
                flash("User already exists")
                return render_template('user_signup.html', form=form)

            # Check if the transactionId already used in AcceptedUsers or RequestedUsers
            accepted_user_ref = db.reference("accepted_users").order_by_child("transactionId").equal_to(transactionId)
            requested_user_ref = db.reference("requested_users").order_by_child("transactionId").equal_to(transactionId)
            if accepted_user_ref.get() or requested_user_ref.get():
                flash("Transaction Id already is Used")
                return render_template('user_signup.html', form=form)

            # Store user data in RequestedUsers node
            requested_user_ref = db.reference("requested_users").child(username)
            new_user_data = {
                'email': email,
                'password': password,
                'transactionId': transactionId,
                'phone_number': phone_number,
                'action': 'pending'
            }
            requested_user_ref.set(new_user_data)

            # Store user data in UserDetails node
            store_user(username, password)

            flash('User registered successfully. Please wait for confirmation!', 'success')
            return render_template('user_signup.html', form=form), 201

        return render_template('user_signup.html', form=form)
    except Exception as e:
        # Delete the user if it is added to requested users and user details
        if 'username' in locals():
            requested_user_ref = db.reference("requested_users").child(username)
            requested_user_ref.delete()
            user_ref = db.reference("user_details").child(username)
            user_ref.delete()

        return jsonify({"message": f"Sign up error: {str(e)}"}), 500


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotForm()
    return render_template('forgot_password.html', form=form)


@app.route('/send_otp_to_user/<string:username>', methods=['POST'])
def sendOTPtoUSER(username):
    try:
        req_user = db.reference("requested_users").child(username).get()
        acc_user = db.reference("accepted_users").child(username).get()

        if (req_user and not acc_user) or (acc_user and not req_user):
            email = req_user['email'] if req_user else acc_user['email']

            genOTP = generateOTP()

            message = Message('Your OTP', sender=app.config['MAIL_USERNAME'], recipients=[email])
            message.body = f'Your OTP is: {genOTP}'
            mail.send(message)

            session['otp'] = genOTP

            return jsonify({"message": "OTP sent to your email", "status": "success"}), 200
        elif not req_user:
            return jsonify({"message": "User Not Found", "status": "Not Found"}), 404

        return jsonify({"message": "Error in sending OTP to the user", "status": "error"}), 404
    except Exception as e:
        return jsonify({"message": f"Error in sending OTP to the user: {str(e)}", "status": "error"}), 404


@app.route('/validate_otp', methods=['POST'])
def verifyOTP():
    try:
        form = ResetForm()
        user_otp = request.form.get('otp')
        if user_otp == session['otp']:
            return redirect(url_for('reset_password'))
        flash('Invalid OTP', 'danger')
        return redirect(url_for('forgot_password'))
    except Exception as e:
        return f"Error in verifying OTP {str(e)}"


@app.route('/reset_password>', methods=['POST'])
def reserPassword():
    try:
        form = ResetForm()
        username = session.get('username')
        new_password = request.form.get('newPassword')
        conform_password = request.form.get('conformPassword')
        if new_password != conform_password:
            flash('Password not matched', 'danger')
            return render_template('reset_password.html', username=session.get('username'), form=form)
        user = db.reference("user_details").child(username)
        user.update({
            "hashed_password": hash_password(new_password)[0],
            "salt": hash_password(new_password)[1]
        })

        acc_user = db.reference("accepted_users").child(username)
        req_user = db.reference("requested_users").child(username)
        if acc_user.get():
            acc_user.update({"password": new_password})
        elif req_user.get():
            req_user.update({"password": new_password})

        flash('Password reset successful!', 'success')
        return redirect(url_for('user_login'))
    except Exception as e:
        return "Error in reseting password" + str(e)



from firebase_admin import db
@app.route('/admin_post_notification', methods=['GET', 'POST'])
def admin_post_notification():
    if not session.get('logged_in'):
        return redirect(url_for('admin_login'))

    form = NotificationForm()

    if form.validate_on_submit():
        title = form.title.data
        link = form.link.data
        visible = form.visible.data

        notification_ref = db.reference('notifications')
        notification_ref.push({
            'title': title,
            'link': link,
            'visible': visible,
            'timestamp': datetime.datetime.now().isoformat()
        })
        flash('Notification posted successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('admin_post_notification.html', form=form)
@app.route('/admin/notifications', methods=['GET'])
def admin_notifications():
    if not session.get('logged_in'):
        return redirect(url_for('admin_login'))

    notification_ref = db.reference('notifications')
    notifications_data = notification_ref.get()

    notifications = []
    if notifications_data:
        notifications = [
            {
                'id': notif_id,
                'title': notif['title'],
                'link': notif['link'],
                'visible': notif['visible'],
                'timestamp': notif['timestamp']
            } for notif_id, notif in notifications_data.items()
        ]

        notifications.sort(key=lambda x: x['timestamp'], reverse=True)

    return render_template('manage_notifications.html', notifications=notifications)


@app.route('/admin/notifications/edit/<string:notification_id>', methods=['GET', 'POST'])
def edit_notification(notification_id):
    if not session.get('logged_in'):
        return redirect(url_for('admin_login'))

    form = NotificationForm()
    notification_ref = db.reference('notifications').child(notification_id)
    notification_data = notification_ref.get()

    if request.method == 'GET':
        form.title.data = notification_data['title']
        form.link.data = notification_data['link']
        form.visible.data = notification_data['visible']

    if form.validate_on_submit():
        title = form.title.data
        link = form.link.data
        visible = form.visible.data

        notification_ref.update({
            'title': title,
            'link': link,
            'visible': visible,
            'timestamp': datetime.datetime.now().isoformat()
        })
        flash('Notification updated successfully!', 'success')
        return redirect(url_for('admin_notifications'))

    return render_template('edit_notification.html', form=form, notification_id=notification_id)


@app.route('/admin/notifications/delete/<string:notification_id>', methods=['POST'])
def delete_notification(notification_id):
    if not session.get('logged_in'):
        return redirect(url_for('admin_login'))

    notification_ref = db.reference('notifications').child(notification_id)
    notification_ref.delete()
    flash('Notification deleted successfully!', 'success')
    return redirect(url_for('admin_notifications'))



# Search for requested users in adminDashboard
@app.route('/requested_users_search', methods=['POST'])
def requested_search():
    try:
        inputSearch = request.json.get('inputSearch')
        requested_users_ref = db.reference('requested_users')
        requested_users = requested_users_ref.order_by_child('username').start_at(inputSearch).end_at(inputSearch + '\uf8ff').get()

        serialized_requested_users = [{key: value for key, value in user.items()} for user in requested_users.values()]

        return jsonify({"message": "Search Success", "requested_users": serialized_requested_users}), 200
    except Exception as e:
        return jsonify({"message": "Error in searching requested users: " + str(e)}), 404


@app.route('/accepted_users_search', methods=['POST'])
def accepted_search():
    try:
        inputSearch = request.json.get('inputSearch')
        accepted_users_ref = db.reference('accepted_users')
        accepted_users = accepted_users_ref.order_by_child('username').start_at(inputSearch).end_at(inputSearch + '\uf8ff').get()

        serialized_accepted_users = [{key: value for key, value in user.items()} for user in accepted_users.values()]

        return jsonify({"message": "Search Success", "accepted_users": serialized_accepted_users}), 200
    except Exception as e:
        return jsonify({"message": "Error in searching accepted users: " + str(e)}), 404


@app.route('/accept_requested_user/<string:username>', methods=['POST'])
def accept_user(username):
    try:
        requested_users_ref = db.reference('requested_users')
        requested_user_ref = requested_users_ref.child(username)
        user_data = requested_user_ref.get()

        if user_data:
            accepted_users_ref = db.reference('accepted_users')
            accepted_users_ref.child(username).set(user_data)
            requested_user_ref.delete()

            return jsonify({"message": "User accepted successfully"}), 200
        else:
            return jsonify({"message": "User not found"}), 404
    except Exception as e:
        return jsonify({"message": "Error accepting user: " + str(e)}), 500


@app.route('/reject_requested_user/<string:username>', methods=['POST'])
def reject_user(username):
    try:
        requested_users_ref = db.reference('requested_users')
        requested_user_ref = requested_users_ref.child(username)
        if user_data := requested_user_ref.get():
            requested_user_ref.delete()
            return jsonify({"message": "User rejected successfully"}), 200
        else:
            return jsonify({"message": "User not found"}), 404
    except Exception as e:
        return jsonify({"message": f"Error rejecting user: {str(e)}"}), 500


@app.route('/delete_accepted_user/<string:username>', methods=['POST'])
def delete_user(username):
    try:
        accepted_users_ref = db.reference('accepted_users')
        user_info_ref = db.reference('user_details')
        accepted_user_ref = accepted_users_ref.child(username)
        user_info_ref = user_info_ref.child(username)
        if user_data := accepted_user_ref.get():
            accepted_user_ref.delete()
            user_info_ref.delete()
            return jsonify({"message": "User deleted successfully"}), 200
        else:
            return jsonify({"message": "User not found"}), 404
    except Exception as e:
        return jsonify({"message": f"Error deleting user: {str(e)}"}), 500


@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('admin_login'))

    try:
        requested_users_ref = db.reference('requested_users')
        requested_users = requested_users_ref.get()
        return render_template('admin_dashboard.html', requested_users=requested_users)
    except Exception as e:
        return f"Admin Dashboard Error: {str(e)}"


@app.route('/accepted_users', methods=['GET', 'POST'])
def accepted_users():
    if not session.get('logged_in'):
        return redirect(url_for('admin_login'))

    try:
        accepted_users_ref = db.reference('accepted_users')
        accepted_users = accepted_users_ref.get()
        return render_template('display_accepted_users.html', accepted_users=accepted_users)
    except Exception as e:
        return "Accepted Users Error: " + str(e)


@app.route('/notifications/<string:username>', methods=['GET'])
def notifications(username):
    if 'username' not in session or session['username'] != username:
        flash('Unauthorized access. Please log in.', 'danger')
        return redirect(url_for('user_login'))

    try:
        notification_ref = db.reference('notifications')
        notifications_data = notification_ref.get()

        notifications = []
        if notifications_data:
            notifications = [
                {
                    'title': notif['title'],
                    'link': notif['link'],
                    'timestamp': notif['timestamp']
                } for notif in notifications_data.values() if notif['visible']
            ]

            # Sort notifications by timestamp
            notifications.sort(key=lambda x: x['timestamp'], reverse=True)

        return render_template('notifications.html', username=username, notifications=notifications)
    except Exception as e:
        print(f"Error retrieving notifications: {str(e)}")
        return f"Error retrieving notifications: {str(e)}"



#User Dashboard
#------------------------------------------
    
@app.route('/user_dashboard/<string:username>', methods=['GET', 'POST'])
def user_dashboard(username):
    form = UserDashboardForm()

    result = caste = ews = gender = locality = phase = colleges = count = None

    try:
        if 'username' in session and session['username'] == username:
            if form.validate_on_submit():
                colleges = form.colleges.data
                caste = form.caste.data
                gender = form.gender.data
                ews = form.ews.data
                locality = form.locality.data
                phase = form.phase.data
                scheme = form.scheme.data

                merit_list = tel_merit_list
                if scheme == 'Telangana BDS':
                    data = tel_dbs
                    ews = "NO"
                    merit_list = tel_merit_list
                elif scheme == 'Telangana AYUSH':
                    data = tel_ayush
                    merit_list = tel_merit_ayush
                elif phase == 'P1':
                    data = data_frame
                elif phase == 'P2':
                    data = data_frame_p2
                elif phase == 'P3':
                    data = data_frame_p3
                elif phase in ['P4', 'P5','P6','P7']:
                    data = data_frame_p4
                elif phase == "ALL" :
                    data=pd.concat([data_frame,data_frame_p2,data_frame_p3,data_frame_p4],join='inner')
                    
                else:
                    return "Error in Tel User Dashboard For Data is Empty", 404
                data = data.drop_duplicates()
                result = filter_data(data, colleges, caste, gender, ews, locality, phase, scheme, merit_list)
                result = result.reset_index(drop=True)
                return render_template('user_dashboard.html', form=form, username=username, result=result, caste=caste,
                                       ews=ews, gender=gender, locality=locality, phase=phase, colleges=colleges,
                                       count=result.shape[0])
            return render_template('user_dashboard.html', form=form, username=username, result=result, caste=caste,
                                   ews=ews, gender=gender, locality=locality, phase=phase)
        else:
            flash('Unauthorized access. Please log in.', 'danger')
            return redirect(url_for('user_login'))

    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return "An error occurred in Tel User DashBoard: " + str(e)


#Andhra User Dashboard
#------------------------------------------

@app.route('/andhraUserDashboard/<string:username>', methods=['GET', 'POST'])
def andhraUserDashboard(username):
    form = AndhraUserDashboardForm()
    result = caste = ews = gender = locality = phase = colleges = count = None

    try:
        if 'username' in session and session['username'] == username:
            if form.validate_on_submit():
                colleges = form.colleges.data
                caste = form.caste.data
                gender = form.gender.data
                ews = form.ews.data
                locality = form.locality.data
                phase = form.phase.data
                scheme = form.scheme.data
                if scheme == 'Andhra Pradesh MBBS':
                    data = andhra_mbbs_list
                    ews = "NO"
                    merit_list = andhra_merit_list
                elif scheme == 'Andhra Pradesh BDS':
                    data = andhra_bds_list
                    ews = "NO"
                    merit_list = andhra_merit_list
                elif scheme == 'Andhra Pradesh AYUSH':
                    data = andhra_aush_list
                    merit_list = andhra_aush_merit_list
                else:
                    data = None
                    merit_list = andhra_merit_list
                    return "Error in Andhra User Dashboard For Data is Empty", 404
                data.drop_duplicates()
                result = filter_data(data, colleges, caste, gender, ews, locality, phase, scheme, merit_list)

                result = result.drop_duplicates()
                result = result.reset_index(drop=True)
                return render_template('andhra_user_dashboard.html', form=form, username=username, result=result, caste=caste,
                                       ews=ews, gender=gender, locality=locality, phase=phase, colleges=colleges, count=result.shape[0])
            return render_template('andhra_user_dashboard.html', form=form, username=username, result=result, caste=caste,
                                   ews=ews, gender=gender, locality=locality, phase=phase, colleges=colleges)
        else:
            flash('Unauthorized access. Please log in.', 'danger')
            return redirect(url_for('user_login'))
        
    except Exception as e:
        # Handle the exception, you can log it or render an error template
        print(f"An error occurred: {str(e)}")
        return "Error in Andhra User Dashboard"+str(e)
#Telanagana management 

@app.route('/telanaganamanagement/<string:username>',methods=['GET','POST'])
def telanaganamanagement(username):
    form=TelanaganaManagementForm()
    result=None
    try:
        if 'username' in session and session['username']==username:
            if request.method == 'POST' and form.validate():
                #Retrive form inputs
                phase=form.phase.data
                category=form.category.data
                locality=form.locality.data
                colleges=form.colleges.data
                data=tel_management.copy()

                if phase=="ALL" and colleges == "ALL Colleges":
                    result = data[(data['Category']==category) &
                                  (data['LOC']==locality)]
                elif phase=="ALL" and colleges != "ALL Colleges":
                    result = data[(data['Category']==category) &
                                  (data['LOC']==locality) & 
                                  (data['COLLEGE']==colleges)]
                elif phase!="ALL" and colleges == "ALL Colleges":
                    result = data[(data['Category']==category) &
                                  (data['LOC']==locality) & 
                                  (data['PHASE']==phase)]
                else:
                    result =  data[(data['Category']==category) &
                                  (data['LOC']==locality) & 
                                  (data['PHASE']==phase) & 
                                  (data['COLLEGE']==colleges)]
                result = result.reset_index(drop=True)
                print("Filtered Result:")
                print(result)

                return render_template('telanagana_management.html', form=form, username=username, result=result)
            return render_template('telanagana_management.html', form=form, username=username, result=result)
        else:
                flash('Unauthorized access. Please log in.', 'danger')
                return redirect(url_for('user_login'))
    except Exception as e:
            # Log the error and render an error message
            print(f"An error occurred: {str(e)}")
            flash('An error occurred. Please try again.', 'danger')
            return redirect(url_for('telanaganamanagement', username=username))



#AP MANAGEMENT  DASHBORD
@app.route('/andhramanagement/<string:username>',methods=['GET','POST'])
def andhramanagement(username):
    form=AndhraManagement()
    result=None
    try:
        if 'username' in session and session['username']==username:
            if request.method == 'POST' and form.validate():
                #Retrive form inputs
                phase=form.phase.data
                category=form.category.data
                locality=form.locality.data
                colleges=form.colleges.data
                data=ap_management.copy()

                if phase=="ALL" and colleges == "ALL Colleges":
                    result = data[(data['Category']==category) &
                                  (data['LOC']==locality)]
                elif phase=="ALL" and colleges != "ALL Colleges":
                    result = data[(data['Category']==category) &
                                  (data['LOC']==locality) & 
                                  (data['COLLEGE']==colleges)]
                elif phase!="ALL" and colleges == "ALL Colleges":
                    result = data[(data['Category']==category) &
                                  (data['LOC']==locality) & 
                                  (data['PHASE']==phase)]
                else:
                    result =  data[(data['Category']==category) &
                                  (data['LOC']==locality) & 
                                  (data['PHASE']==phase) & 
                                  (data['COLLEGE']==colleges)]
                result = result.reset_index(drop=True)
                print("Filtered Result:")
                print(result)

                return render_template('ap_management.html', form=form, username=username, result=result)
            return render_template('ap_management.html', form=form, username=username, result=result)
        else:
                flash('Unauthorized access. Please log in.', 'danger')
                return redirect(url_for('user_login'))
    except Exception as e:
            # Log the error and render an error message
            print(f"An error occurred: {str(e)}")
            flash('An error occurred. Please try again.', 'danger')
            return redirect(url_for('andhramanagement', username=username))

#All India Dashboaed
#------------------------------------------

    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return "Error in Andhra User Dashboard" + str(e)


@app.route('/allIndiaDashboard/<string:username>', methods=['GET', 'POST'])
def allIndiaDashboard(username):
    form = AllIndiaForm()
    result = None

    try:
        if 'username' in session and session['username'] == username:
            if request.method == 'POST' and form.validate():
                scheme = form.scheme.data
                quota = form.quota.data
                phase = form.phase.data
                colleges = form.colleges.data
                caste = form.caste.data

                data = all_india_list.copy()

                if colleges == "All Colleges":
                    result = data[(data['Allotted Quota'] == quota) &
                                  (data['Course'] == scheme) &
                                  (data['CandidateCategory'] == caste) &
                                  (data['Phase'] == phase)]
                else:
                    result = data[(data['Allotted Institute'] == colleges) &
                                  (data['Allotted Quota'] == quota) &
                                  (data['Course'] == scheme) &
                                  (data['CandidateCategory'] == caste) &
                                  (data['Phase'] == phase)]

                result = result.reset_index(drop=True)

                print("Filtered Result:")
                print(result)

                return render_template('all_india_dashboard.html', form=form, username=username, result=result)

            return render_template('all_india_dashboard.html', form=form, username=username, result=result)

        else:
            flash('Unauthorized access. Please log in.', 'danger')
            return redirect(url_for('user_login'))

    except Exception as e:
        print(f"An error occurred: {str(e)}")
        flash('An error occurred. Please try again.', 'danger')
        return redirect(url_for('allIndiaDashboard', username=username))


@app.route('/results_page')
def results_page():
    return render_template('Hello')


def filter_data(df, colleges, caste, gender, ews, locality, phase, scheme, merit_list):
    check = False
    if colleges == 'ALL Colleges':
        if gender != 'ALL':
            filtered_data = df[(df['CAT'] == caste) & (df['EWS'] == ews) & (df['SX'] == gender) & (df['LOC'] == locality) & (df['PHASE'] == phase)].copy()
            check = True
        else:
            filtered_data = df[(df['CAT'] == caste) & (df['EWS'] == ews) & (df['LOC'] == locality) & (df['PHASE'] == phase)].copy()
    else:
        if gender != 'ALL':
            check = True
            filtered_data = df[(df['COLLEGE'] == colleges) & (df['CAT'] == caste) & (df['EWS'] == ews) & (df['SX'] == gender) & (df['LOC'] == locality) & (df['PHASE'] == phase)].copy()
        else:
            filtered_data = df[(df['COLLEGE'] == colleges) & (df['CAT'] == caste) & (df['EWS'] == ews) & (df['LOC'] == locality) & (df['PHASE'] == phase)].copy()

    filtered_data.loc[:, 'RCR'] = filtered_data.apply(lambda row: RCR(merit_list, row['RANK'], row['LOC'], row['CAT']), axis=1)
    filtered_data.loc[:, 'OCR'] = filtered_data.apply(lambda row: OCR(merit_list, row['RANK'], row['CAT']), axis=1)
    filtered_data.loc[:, 'RCG'] = filtered_data.apply(lambda row: RCG(merit_list, row['RANK'], row['CAT'], row['SX']), axis=1)
    filtered_data.loc[:, 'OGR'] = filtered_data.apply(lambda row: OGR(merit_list, row['RANK'], row['SX']), axis=1)
    filtered_data.loc[:, 'Marks'] = filtered_data.apply(lambda row: getmarks(merit_list, row['RANK']), axis=1)
    filtered_data.loc[:, 'State_Rank'] = filtered_data.apply(lambda row: stateRank(merit_list, row['RANK']), axis=1)

    if check:
        filtered_data = filtered_data[['COLLEGE', 'RANK', 'Marks', 'State_Rank', 'RCR', 'OCR', 'RCG', 'OGR']]
    else:
        filtered_data = filtered_data[['COLLEGE', 'SX', 'RANK', 'Marks', 'State_Rank', 'RCR', 'OCR', 'RCG', 'OGR']]

    return filtered_data.sort_values(by='RANK')


def RCR(df, rank, locality, caste):
    if locality != 'OU':
        filtered_data = df[(df['NEET Rank'] <= rank) & (df['Local'] != 'OU') & (df['Category'] == caste)]
    else:
        filtered_data = df[(df['NEET Rank'] <= rank) & (df['Local'] == 'OU') & (df['Category'] == caste)]
    return filtered_data.shape[0]


def OCR(df, rank, caste):
    filtered_data = df[(df['NEET Rank'] <= rank) & (df['Category'] == caste)]
    return filtered_data.shape[0]


def RCG(df, rank, caste, gender):
    filtered_data = df[(df['NEET Rank'] < rank) & (df['Category'] == caste) & (df['Gender'] == gender)]
    return filtered_data.shape[0] + 1


def OGR(df, rank, gender):
    filtered_data = df[(df['NEET Rank'] < rank) & (df['Gender'] == gender)]
    return filtered_data.shape[0] + 1


def getmarks(df, rank):
    if rank is not None:
        filtered_data = df[(df['NEET Rank'] == rank)]
        filtered_data = filtered_data.loc[:, ['NEET Score']]
        if not filtered_data.empty:
            x = filtered_data.iloc[0]['NEET Score']
            return x
    else:
        return None


def stateRank(df, rank):
    if rank is not None:
        filtered_data = df[(df['NEET Rank'] == rank)]
        filtered_data = filtered_data.loc[:, ['State Rank']]
        if not filtered_data.empty:
            x = filtered_data.iloc[0]['State Rank']
            return x
    else:
        return None


@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('logged_in', None)
    flash('Logged out successfully!', 'success')
    return redirect(url_for('user_login'))


# Custom error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    logging.error(f"Server Error: {e}, route: {request.url}")
    return render_template('404.html'), 500


# Run the app
if __name__ == '__main__':
    logging.basicConfig(filename='error.log', level=logging.ERROR)
    app.run(debug=True)

from flask import Flask, render_template, redirect, url_for,  flash, get_flashed_messages, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo
from flask_mongoengine import Document
from flask_mongoengine import MongoEngine
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from mongoengine.errors import NotUniqueError
from flask_socketio import SocketIO,emit
import datetime
from pymongo import MongoClient


app = Flask(__name__, static_folder='static')
app.config['SECRET_KEY'] = 'your-secret-key'

app.config['MONGODB_SETTINGS'] = {
    'db': 'chatapp',  # Database name
    'host': 'mongodb+srv://ompatel5044:newpass@cluster0.ampxsg8.mongodb.net/?retryWrites=true&w=majority'
}

db = MongoEngine(app)
bcrypt = Bcrypt(app)
socketio = SocketIO(app)

@socketio.on('message')
def handle_message(data):
    message_content = data['message']
    sender = current_user.username
    message = Message(content=message_content, sender=sender)
    message.save()

    emit('message', {'message': message_content, 'username': sender}, broadcast=True)

# Setup Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.objects(id=user_id).first()

class User(db.Document):
    username = db.StringField(required=True, unique=True)
    email = db.StringField(required=True, unique=True)
    password = db.StringField(required=True)

    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)
    
    @property
    def is_active(self):
        return True
    
    def get_id(self):
        return str(self.id)
    
    @property
    def is_authenticated(self):
        return True  # Modify this property method

    @property
    def is_anonymous(self):
        return False


    
class Message(db.Document):
    content = db.StringField(required=True)
    sender = db.StringField(required=True)
    timestamp = db.DateTimeField(default=datetime.datetime.utcnow)

class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')

@app.route('/')
def home():
    return render_template('home.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        try:
            new_user = User(
                username=form.username.data,
                email=form.email.data,
            )
            new_user.set_password(form.password.data)  # Hash the password
            new_user.save()
            flash('Account created successfully!', 'success')
        except NotUniqueError as e:
            flash('Username or email already exists. Please log in.', 'danger')
            return redirect(url_for('login'))
    return render_template('signup.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.objects(email=form.email.data).first()
        if user:
            if user.check_password(form.password.data):
                login_user(user)  # Initiate user session with Flask-Login
                flash('Logged in successfully!', 'success')
                return redirect(url_for('home'))
            else:
                flash('Invalid email or password', 'danger')
        else:
            flash('User does not exist', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()  # Terminate user session with Flask-Login
    flash('Logged out successfully!', 'success')
    return redirect(url_for('home'))

@app.route('/chat', methods=['GET', 'POST'])
@login_required
def chat():
    if request.method == 'POST':
        message_content = request.form.get('message')
        sender = current_user.username
        message = Message(content=message_content, sender=sender)
        message.save()
        socketio.emit('message', {'message': message_content, 'username': sender}, broadcast=True)

    messages = Message.objects()  # Retrieve all messages from the database
    return render_template('chat.html', messages=messages)

if __name__ == "__main__":
    socketio.run(app, debug=True)

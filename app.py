from flask import  Flask, render_template, url_for, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = ''
db = SQLAlchemy(app)

app.config['MAIL_SERVER'] = ''
app.config['MAIL_PORT'] = ''
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'mathesphiwe689@gmail.com'
app.config['MAIL_PASSWORD'] = ''

mail = Mail(app)

time_slots = ['9:00 AM', '10:00 AM', '11:00 AM', '2:00 PM', '3:00 PM', '4:00 PM']
contents = ['Consultation', 'Treatment', 'Check-up', 'Other']
shippings = ['Collecting: R90', 'Delivery: R125']

login_mananger = LoginManager()
login_mananger.init_app(app)
login_mananger.login_view = "login"

@login_mananger.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(),Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")

def validate_username(self, username):
    existing_user_username = User.query.filter_by(
        username=username.data).first()
    if existing_user_username:
        raise ValidationError(
            "That username already exists. please choose a different one.")

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(),Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/services', methods=['GET', 'POST'])
def services():
    return render_template('Services.html')

@app.route('/medicine', methods=['GET', 'POST'])
def medicine():
    return render_template('medicine.html')

@app.route('/about', methods=['GET', 'POST'])
def about():
    return render_template('about.html')

@app.route('/Family Planning', methods=['GET', 'POST'])
def FamilyPlanning():
    return render_template('familyPlanning.html')

@app.route('/book_appointment', methods=['GET', 'POST'])
def book_appointment():
    if request.method == 'POST':

        name = request.form['name']
        surname = request.form['surname']
        email = request.form['email']
        phone = request.form['phone']
        time_slot = request.form['time_slot']
        content = request.form['content']

        msg = Message('New Appointment',
                      sender='mathesphiwe689@gmail.com',  # Your email address
                      recipients=['nazireemathe@gmail.com'])  # Recipient email address
        msg.body = f'New appointment details:\nName: {name}\nSurname: {surname}\nEmail: {email}\nPhone: {phone}\nTime Slot: {time_slot}\nContent: {content}'
        mail.send(msg)


        return "Appointment booked successfully! Thank you."


    return render_template('book_appointment.html', time_slots=time_slots, contents=contents)

@app.route('/panado', methods=['GET', 'POST'])
def panado():
    if request.method == 'POST':

        name = request.form['name']
        surname = request.form['surname']
        email = request.form['email']
        phone = request.form['phone']
        shipping = request.form['shipping']


        msg = Message('Order for Panado:',
                      sender='mathesphiwe689@gmail.com',  # Your email address
                      recipients=['nazireemathe@gmail.com'])  # Recipient email address
        msg.body = f'ordered by:\nName: {name}\nSurname: {surname}\nEmail: {email}\nPhone: {phone}\nShipping: {shipping}'
        mail.send(msg)




    return render_template('panado.html', shippings=shippings)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

if __name__ == '__main__':
    app.run(debug=True)

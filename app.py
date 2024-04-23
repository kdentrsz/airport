from flask import Flask, request, render_template, redirect, url_for
import requests
from pyairports.airports import Airports
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///airportss.db'
app.config['SECRET_KEY'] = os.urandom(24)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
app.permanent_session_lifetime = timedelta(minutes=5)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    chosen_airport = db.relationship('UserChosenAirport', backref='user', lazy='joined', uselist=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class UserChosenAirport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    iata_code = db.Column(db.String(3), nullable=False)
    chosen_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@login_required
def index():
    if current_user.is_authenticated:
        return redirect(url_for('airports'))
    else:
        return redirect(url_for('login'))

@app.route('/profile')
@login_required
def profile():
    airports = Airports()
    chosen_airport = current_user.chosen_airport
    if chosen_airport:
        iata_code = chosen_airport.iata_code
        chosen_at = chosen_airport.chosen_at
        airport = airports.airport_iata(iata_code)
        if airport:
            city = airport.city
        else:
            city = None
    else:
        iata_code = None
        chosen_at = None
        city = None

    return render_template('profile.html', email=current_user.email, iata_code=iata_code, chosen_at=chosen_at, city=city)

@app.route('/profile/delete_choice', methods=['POST'])
@login_required
def delete_choice():
    current_user.chosen_airport = None
    db.session.commit()
    return redirect(url_for('profile'))


@app.route('/profile/change_email', methods=['GET', 'POST'])
@login_required
def change_email():
    if request.method == 'POST':
        new_email = request.form.get('new_email')
        existing_user = User.query.filter_by(email=new_email).first()
        if existing_user:
            return render_template('change_email.html', error='Email already exists.')
        current_user.email = new_email
        db.session.commit()
        return redirect(url_for('profile'))
    return render_template('change_email.html')


def get_data(origin):
    url = "https://travelpayouts-travelpayouts-flight-data-v1.p.rapidapi.com/v1/city-directions"
    headers = {
        "X-Access-Token": "fdc0691b402e78b53216fa63b992d982",
        "X-RapidAPI-Key": "d6cd402b02msh42bcc1450f4a1a5p194bdbjsneced90c45126",
        "X-RapidAPI-Host": "travelpayouts-travelpayouts-flight-data-v1.p.rapidapi.com"
    }
    querystring = {"currency": "EUR", "origin": origin}
    response = requests.get(url, headers=headers, params=querystring)
    return response.json()


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('airports'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('airports'))
        else:
            return render_template('login.html', error='Invalid email or password.')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('airports'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user:
            return render_template('register.html', error='Email already registered.')
        new_user = User(email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('airports'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/airports', methods=['GET', 'POST'])
@login_required
def airports():
    origin = request.args.get('origin')
    if request.method == 'POST':
        iata_code = request.form.get('iata_code')
        chosen_airport = current_user.chosen_airport
        if chosen_airport:
            chosen_airport.iata_code = iata_code
            chosen_airport.chosen_at = datetime.utcnow()
        else:
            chosen_airport = UserChosenAirport(user_id=current_user.id, iata_code=iata_code)
            db.session.add(chosen_airport)
            current_user.chosen_airport = chosen_airport
        db.session.commit()

    if origin:
        data = get_data(origin)
        if data:
            my_list = []
            find_destinations(data, my_list)
            airports = Airports()
            results = []
            for iata_code in my_list:
                airport = airports.airport_iata(iata_code)
                if airport:
                    is_chosen = False
                    if current_user.chosen_airport and current_user.chosen_airport.iata_code == iata_code:
                        is_chosen = True
                    results.append({
                        "city": airport.city,
                        "iata_code": iata_code,
                        "is_chosen": is_chosen
                    })
            return render_template('results.html', results=results)
        else:
            return render_template('results.html', error="Couldn't retrieve data from the API")
    else:
        return render_template('index.html')

def find_destinations(data, my_list):
    if isinstance(data, dict):
        for key, value in data.items():
            if key == "destination":
                my_list.append(value)
            else:
                find_destinations(value, my_list)
    elif isinstance(data, list):
        for item in data:
            find_destinations(item, my_list)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
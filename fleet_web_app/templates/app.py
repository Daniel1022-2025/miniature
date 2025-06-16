# Flask-based web version of the Fleet Management System

from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, date
from werkzeug.security import generate_password_hash, check_password_hash
import csv
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///fleet_web.db'
db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(10), nullable=False)

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    driver = db.Column(db.String(80))
    date = db.Column(db.Date)
    start_time = db.Column(db.String(10))
    stop_time = db.Column(db.String(10))
    start_mileage = db.Column(db.Integer)
    stop_mileage = db.Column(db.Integer)
    purpose = db.Column(db.String(200))
    fuel_litres = db.Column(db.Float)

class Maintenance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    driver = db.Column(db.String(80))
    date = db.Column(db.Date)
    issue = db.Column(db.String(200))
    status = db.Column(db.String(20), default='Pending')

# Routes
@app.route('/')
def home():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        session['user'] = user.username
        session['role'] = user.role
        return redirect(url_for('dashboard'))
    flash("Invalid credentials")
    return redirect(url_for('home'))

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('home'))
    if session['role'] == 'boss':
        return render_template('boss_dashboard.html')
    return render_template('driver_dashboard.html')

@app.route('/submit_log', methods=['POST'])
def submit_log():
    log = Log(
        driver=session['user'],
        date=date.today(),
        start_time=request.form['start_time'],
        stop_time=request.form['stop_time'],
        start_mileage=int(request.form['start_mileage']),
        stop_mileage=int(request.form['stop_mileage']),
        purpose=request.form['purpose'],
        fuel_litres=float(request.form['fuel_litres'])
    )
    db.session.add(log)
    db.session.commit()
    flash("Log submitted successfully")
    return redirect(url_for('dashboard'))

@app.route('/mechanical_request', methods=['POST'])
def mechanical_request():
    issue = request.form['issue']
    request_entry = Maintenance(driver=session['user'], date=date.today(), issue=issue)
    db.session.add(request_entry)
    db.session.commit()
    flash("Maintenance request submitted")
    return redirect(url_for('dashboard'))

@app.route('/weekly_report')
def weekly_report():
    if session.get('role') != 'boss':
        return redirect(url_for('dashboard'))
    logs = Log.query.all()
    report = {}
    for log in logs:
        year, week, _ = log.date.isocalendar()
        key = (log.driver, year, week)
        distance = log.stop_mileage - log.start_mileage
        if key not in report:
            report[key] = [0, 0]
        report[key][0] += distance
        report[key][1] += log.fuel_litres
    formatted = []
    for k, v in report.items():
        efficiency = v[0] / v[1] if v[1] else 0
        formatted.append((k[0], f"{k[1]}-W{k[2]}", v[0], v[1], round(efficiency, 2)))
    return render_template('weekly_report.html', report=formatted)

@app.route('/register', methods=['POST'])
def register():
    if session.get('role') != 'boss':
        return redirect(url_for('dashboard'))
    username = request.form['username']
    password = generate_password_hash(request.form['password'])
    user = User(username=username, password=password, role='driver')
    db.session.add(user)
    db.session.commit()
    flash("Driver registered successfully")
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

# Initialize DB and create admin
@app.before_first_request
def setup():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', password=generate_password_hash('admin123'), role='boss')
        db.session.add(admin)
        db.session.commit()

if __name__ == '__main__':
    app.run(debug=True)

# HTML templates will be generated next

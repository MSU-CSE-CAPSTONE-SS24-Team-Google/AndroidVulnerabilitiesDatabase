# Author: Prof. MM Ghassemi <ghassem3@msu.edu>

#--------------------------------------------------
# Import Requirements
#--------------------------------------------------
import os
from flask import Flask
from flask_socketio import SocketIO
from flask_failsafe import failsafe
from flask import Flask, render_template
import mysql.connector
# from flask_sqlalchemy import SQLAlchemy

socketio = SocketIO()

#--------------------------------------------------
# Create a Failsafe Web Application
#--------------------------------------------------
@failsafe
def create_app(debug=False):
	app = Flask(__name__)
	current_working_directory = os.listdir('flask_app')
	
	# print output to the console

	print(current_working_directory)
 	
  
	next_dir = os.listdir()
	
	# print output to the console
	print(next_dir)
	os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = 'flask_app/solid-gamma-411111-a377f0b395cf.json'
 	# This will prevent issues with cached static files
	app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
	app.debug = debug
	# The secret key is used to cryptographically-sign the cookies used for storing the session data.
	app.secret_key = 'AKWNF1231082fksejfOSEHFOISEHF24142124124124124iesfhsoijsopdjf'
 
	# MySQL configuration
	db_config = {
		'host': '34.41.151.234',
		'user': 'bocchial',
		'password': 'password',
		'database': 'vulnerabilities'
	}
	# Establish a MySQL connection

 
	@app.route('/dashboard')
	def dashboard():
		connection = mysql.connector.connect(**db_config)
		cursor = connection.cursor()
		# Fetch data from the MySQL database (replace 'your_table' with your actual table name)
		query = "SELECT * FROM asb;"
		cursor.execute(query)
		data = cursor.fetchall()

		# Render the HTML template and pass the data to it
		return render_template('dashboard.html', data=data)
 
	# Connect to GCS mySQL database
	app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://bocchial:password@34.41.151.234/vulnerabilities'
	# db = SQLAlchemy(app)
 
	# class User(db.Model):
	# 	id = db.Column(db.Integer, primary_key=True)
	# 	username = db.Column(db.String(80), unique=True, nullable=False)
	# 	email = db.Column(db.String(120), unique=True, nullable=False)
 
 
	socketio.init_app(app)
	with app.app_context():
		from . import routes
		return app

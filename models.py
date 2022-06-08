from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(20), nullable=False)
    lastname = db.Column(db.String(20))
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.Text, nullable=False)

class Bookings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    booking_date = db.Column(db.Date, default = datetime.today())
    status = db.Column(db.Boolean,nullable=False,default=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'),nullable=False)


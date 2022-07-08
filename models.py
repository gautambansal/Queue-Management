from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(20), nullable=False)
    lastname = db.Column(db.String(20))
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.Text, nullable=False)
    isAdmin = db.Column(db.Boolean,nullable=False,default=False)

class Bookings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    booking_date = db.Column(db.DateTime, default = datetime.utcnow)
    status = db.Column(db.Boolean,nullable=False,default=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'),nullable=False)
    order_id = db.Column(db.String(100), unique=True, nullable=False)
    transaction_id = db.Column(db.String(100))
    txn_mode = db.Column(db.String(20))
    amount = db.Column(db.Integer)


    

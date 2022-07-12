import functools
import PaytmChecksum
import requests
import json
import uuid
import json
from flask import Flask, jsonify, request,render_template,session,g,redirect,url_for,flash
from sqlalchemy import desc, false
from models import db,Users,Bookings
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = 'super secret key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:mysql@localhost/major'

with app.app_context():
   db.init_app(app)
   db.create_all()


#login form
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')

@app.route('/signup' , methods=['GET','POST'])
def signup():
    if request.method == 'POST':
    #    print(request.form)
        email = request.form['email']
        password = request.form['password']
        firstname = request.form['firstname']
        lastname = request.form['lastname']

        user = Users.query.filter_by(email=email).first()

        if user:
            return render_template('signUp.html',msg='Email already exists')
        
        try:
            newUser = Users()
            newUser.firstname = firstname
            newUser.lastname = lastname
            newUser.email = email
            newUser.password = generate_password_hash(password) 
            db.session.add(newUser)
            db.session.commit()

        except Exception as e:
            return render_template('signUp.html',msg='Something went wrong')

        return redirect(url_for('adminLogin')) 
    return render_template('signUp.html')
        
@app.route('/' , methods=['GET'])
def home():
    return render_template('home.html')
    
@app.route('/login' , methods=['GET','POST'])
def adminLogin():
    form = LoginForm()
    if request.method == 'GET':
        return render_template('adminLogin.html', form=form)
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Locate user
        #email is used as username
       
        user = Users.query.filter_by(email=username).first()
   
        if user and check_password_hash(user.password, password):        
            session.clear()
            #storing user_id in the session
            #it will be used to check if admin is logged in
            session['user_id'] = user.id
            if user.isAdmin is True:
                return  redirect(url_for('adminDashboard'))    
            return  redirect(url_for('dashboard'))
        
        return render_template( 'adminLogin.html', msg='Wrong user or password', form=form)



# checks if a user id is stored in the session

@app.before_request
def load_logged_in_user():
    user = session.get('user_id')
    if user is None:
        g.user = None
    else:
        g.user = user

# This function will check if user is logged in or not

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('adminLogin'))

        return view(**kwargs)

    return wrapped_view

# This function will check if logged in user is admin or not
def admin_login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('adminLogin'))
        user = Users.query.filter_by(id=g.user).first()
        if user.isAdmin is False:
            return redirect(url_for('adminLogin'))

        return view(**kwargs)

    return wrapped_view


#Logout feature

@app.route('/logout')
@login_required
def logout():
    session.clear()
    return redirect(url_for('adminLogin'))


@app.route('/admin',methods = ['GET'])
@admin_login_required
@login_required
def adminDashboard():
    bookings = Bookings.query.filter_by(status=True).all()
    return render_template('adminDashboard.html',bookings = bookings)

@app.route('/home',methods = ['GET','POST'])
@login_required
def dashboard():
    bookings = Bookings.query.filter_by(user_id=g.user).order_by(desc(Bookings.booking_date)).all()
    all_bookings = Bookings.query.filter_by(status=True).all()
    tot = Bookings.query.filter_by(status=True).count()
    num = 1
    for booking in all_bookings:
        if booking.user_id==g.user:
            break
        num+=1
    latest_booking = Bookings.query.filter_by(user_id=g.user , status=True).first()
    #print(num)
    return render_template('dashboard.html',bookings = bookings,latest=latest_booking,turn = num,tot=tot)

@app.route('/join',methods = ['GET','POST'])
@login_required
def joinQ():
    
    paytmParams = dict()
    orderId = str(uuid.uuid1().hex)
    print(orderId)
    paytmParams["body"] = {
        "requestType"   : "Payment",
        "mid"           : "yqIOLs05230201544957",
        "websiteName"   : "WEBSTAGING",
        "orderId"       : orderId,
        "callbackUrl"   : url_for('checkout'),
        "txnAmount"     : {
            "value"     : "100.00",
            "currency"  : "INR",
        },
        "userInfo"      : {
            "custId"    : g.user,
        },
    }

    # Generate checksum by parameters we have in body
    # Find your Merchant Key in your Paytm Dashboard at https://dashboard.paytm.com/next/apikeys 
    checksum = PaytmChecksum.generateSignature(json.dumps(paytmParams["body"]),"pRXhFwWqozggJi1J")

    paytmParams["head"] = {
        "signature"    : checksum
    }

    post_data = json.dumps(paytmParams)

    # for Staging
    url = "https://securegw-stage.paytm.in/theia/api/v1/initiateTransaction?mid=yqIOLs05230201544957&orderId="+orderId

    # for Production
    # url = "https://securegw.paytm.in/theia/api/v1/initiateTransaction?mid=YOUR_MID_HERE&orderId=ORDERID_98765"
    response = requests.post(url, data = post_data, headers = {"Content-type": "application/json"}).json()
    #print(response['body']['txnToken']) 
    token = response['body']['txnToken']
    return render_template('checkout.html',orderId=orderId,token=token)
    

@app.route('/checkout',methods = ['GET','POST'])
@login_required
def checkout():
    paytmParams = dict()
    paytmParams = request.form.to_dict()
    print(paytmParams)
    paytmChecksum = paytmParams['CHECKSUMHASH']
    paytmParams.pop('CHECKSUMHASH', None)
    isVerifySignature = PaytmChecksum.verifySignature(paytmParams, "pRXhFwWqozggJi1J",paytmChecksum)
    
    if isVerifySignature and paytmParams['RESPCODE']=='01':
        try:
            newBooking = Bookings()
            newBooking.user_id = g.user 
            newBooking.order_id = paytmParams['ORDERID']
            newBooking.transaction_id = paytmParams['TXNID']
            newBooking.amount = int(float(paytmParams['TXNAMOUNT']))
            newBooking.txn_mode = "Online"
            db.session.add(newBooking)
            db.session.commit()

        except Exception as e:
            #initiate a refund
            return render_template('fail.html',msg = "Any amount deducted will be credit back to your account soon." )
            print(e)

        return redirect(url_for('dashboard'))

        
    else:
        return render_template('fail.html',msg = paytmParams['RESPMSG'] )
    

@app.route('/view/<int:booking_id>',methods = ['GET','POST'])
@login_required
def viewBooking(booking_id):
    curr_booking = Bookings.query.get(booking_id)
    return render_template('viewbooking.html',booking=curr_booking)

@app.route('/deactive/<int:booking_id>',methods = ['GET','POST'])
@admin_login_required
@login_required
def deactiveBooking(booking_id):
    curr_booking = Bookings.query.get(booking_id)

    curr_booking.status = False
    try:
        db.session.commit()
        flash("success")
    except:
        flash("Bad Request")

    return  redirect(url_for('adminDashboard'))

@app.route('/bookoffline',methods = ['GET','POST'])
@admin_login_required
@login_required
def offlineBooking():
    orderId = str(uuid.uuid1().hex)
    try:
        newBooking = Bookings()
        newBooking.user_id = g.user 
        newBooking.order_id = orderId
        newBooking.amount = 100
        newBooking.txn_mode = "Offline"
        db.session.add(newBooking)
        db.session.commit()

    except Exception as e:
        print(e)

    return render_template('offlinebooking.html',booking=newBooking)

if __name__ == '__main__':
    app.run(debug=True ,port=8000)
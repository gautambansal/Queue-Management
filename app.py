import functools
import json
from flask import Flask, jsonify, request,render_template,session,g,redirect,url_for
from models import db,Users
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

#Logout feature

@app.route('/logout')
@login_required
def logout():
    session.clear()
    return redirect(url_for('adminLogin'))


@app.route('/home',methods = ['GET'])
@login_required
def dashboard():
    #forms = Forms.query.filter_by(user_id=g.user).order_by(desc(Forms.creation_date)).all() 
    return render_template('dashboard.html')


if __name__ == '__main__':
    app.run(debug=True ,port=8000)
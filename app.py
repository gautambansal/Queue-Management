from flask import Flask, jsonify, request,render_template,session,g,redirect,url_for

app = Flask(__name__)
app.secret_key = 'super secret key'

@app.route('/' , methods=['GET'])
def home():
    return render_template('home.html')


if __name__ == '__main__':
    app.run(debug=True ,port=8000)
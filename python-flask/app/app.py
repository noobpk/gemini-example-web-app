import os
import bcrypt
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template
from flask import jsonify, request, send_from_directory
from flask_jwt_extended import JWTManager
from flask_jwt_extended import jwt_required, create_access_token, set_access_cookies, get_jwt, get_jwt_identity, \
    unset_jwt_cookies, current_user
from waitress import serve
from werkzeug.utils import secure_filename

from app.model import db, User
from app.seeder import Seeder
from gemini_self_protector import GeminiManager

def create_app():
    app = Flask(__name__, template_folder='template', static_folder='template/assets')

    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config["JWT_COOKIE_SECURE"] = False
    app.config["JWT_CSRF_METHODS"] = ["PUT", "PATCH", "DELETE"]
    app.config["JWT_TOKEN_LOCATION"] = ["cookies", "headers"]
    app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=12)

    db.init_app(app)

    with app.app_context():
        print("Drop Database.........")
        db.drop_all()
        print("Init Database.........")
        db.create_all()
        print("Init Data Seed.........")
        Seeder.seedData()
        print("DataSeeded.........")
    return app

app = create_app()

gemini = GeminiManager(license_key=os.getenv("GEMINI_LICENSE_KEY"), protect_mode=os.getenv("GEMINI_GLOBAL_PROTECT_MODE"))

jwt = JWTManager(app)

@jwt.unauthorized_loader
def my_unauthorized_callback(temp):
    return jsonify({
        "status": "Fail",
        "message": "Missing Authentication Header"
    })

@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.id

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(id=identity).one_or_none()

@app.after_request
def refresh_expiring_jwts(response):
    try:
        exp_timestamp = get_jwt()["exp"]
        now = datetime.now(timezone.utc)
        target_timestamp = datetime.timestamp(now + timedelta(minutes=30))
        if target_timestamp > exp_timestamp:
            access_token = create_access_token(identity=get_jwt_identity())
            # set_access_cookies(response, access_token)
        return response
    except (RuntimeError, KeyError):
        # Case where there is not a valid JWT. Just return the original response
        return response

@app.route('/')
@gemini.flask_protect_extended()
def index():
    return render_template('index.html')

@app.route('/api/login', methods=['POST'])
@gemini.flask_protect_extended(protect_mode='monitor')
def login():
    username = request.json['username']
    password = request.json['password']
    check_username = User.query.filter_by(username=username).first()
    if check_username:
        check_pass = bcrypt.checkpw(password.encode("utf-8"), check_username.password)
        if check_pass:
            access_token = create_access_token(identity=check_username)
            response = jsonify({
                "status": "Success",
                "message": "Login successful",
                "access_token": access_token
                })
            return response
        else:
            return jsonify({
            "status": "Fail",
            "message": "Incorrect Username or Password"
            }), 401
    else:
        return jsonify({
            "status": "Fail",
            "message": "Incorrect Username or Password"
            }), 401

# Run production
if app.config.get("ENV") == "production":
    serve(app, host='0.0.0.0', port=3000, url_scheme='https')

# main driver function
if __name__ == '__main__':
    # run() method of Flask class runs the application
    # on the local development server.
    app.run(debug=True, port=3000)
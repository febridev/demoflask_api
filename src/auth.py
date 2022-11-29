from flask import Blueprint, app, request,jsonify
from src.constants.http_status_codes import HTTP_200_OK, HTTP_201_CREATED, HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED, HTTP_409_CONFLICT
from werkzeug.security import check_password_hash,generate_password_hash
import validators
from src.database import Tuser, db


auth = Blueprint("auth",__name__,url_prefix="/api/v1/auth")

@auth.post('/register')
def register():
    username = request.json['username']
    email = request.json['email']
    password = request.json['password']

    # validation
    if len(password) < 6:
        return jsonify({'error':"Password Too Short"}), HTTP_400_BAD_REQUEST

    if len(username) < 3:
        return jsonify({'error':"Username Too Short"}), HTTP_400_BAD_REQUEST
    
    if not username.isalnum() or " " in username:
        return jsonify({'error':"Username should be alphanumeric, also no space"}), HTTP_400_BAD_REQUEST
    
    if not validators.email(email):
        return jsonify({'error':"Email is not valid"}), HTTP_400_BAD_REQUEST
    
    if Tuser.query.filter_by(email=email).first() is not None:
        return jsonify({'error':"Email is taken"}), HTTP_409_CONFLICT
    
    if Tuser.query.filter_by(username=username).first() is not None:
        return jsonify({'error':"Username is taken"}), HTTP_409_CONFLICT
    
    #hash password
    pwd_hash = generate_password_hash(password)
    
    # insert 
    tuser = Tuser(username=username, email=email, password=pwd_hash)
    # db.connection()
    db.session.add(tuser)
    db.session.commit

    return jsonify({
        'message':"User Created",
        'user': {
            'username': username, 'email':email
        }
    }), HTTP_201_CREATED

    # return "User Created"

@auth.get('/me')
def me():
    return {"user":"me"}

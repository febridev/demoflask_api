from flask import Blueprint, app, request,jsonify
from src.constants.http_status_codes import HTTP_200_OK, HTTP_201_CREATED, HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED, HTTP_409_CONFLICT
from werkzeug.security import check_password_hash,generate_password_hash
import validators
from src.database import Tuser, db
from flask_jwt_extended import jwt_required, create_access_token, create_refresh_token, get_jwt_identity


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
    print(tuser)
    db.session.add(tuser)
    db.session.commit()

    return jsonify({
        'message':"User Created",
        'user': {
            'username': username, 'email': email
        }
    }), HTTP_201_CREATED

    # return "User Created"

@auth.post('/login')
def login():
    email = request.json.get('email','')
    password = request.json.get('password','')

    user = Tuser.query.filter_by(email=email).first()
    
    #check password
    if user:
        is_pass_correct = check_password_hash(user.password, password)

        if is_pass_correct:
            refresh = create_refresh_token(identity=user.id)
            access = create_access_token(identity=user.id)

            return jsonify({
                'user': {
                    'refresh':refresh,
                    'access':access,
                    'username':user.username,
                    'email':user.email
                }
            }), HTTP_200_OK
    
    return jsonify({'error':"Wrong Credentials!!"}), HTTP_401_UNAUTHORIZED

@auth.get('/me')
@jwt_required()
def me():
    user_id = get_jwt_identity()
    user = Tuser.query.filter_by(id=user_id).first()
    return jsonify({
        'username': user.username,
        'email': user.email
    }), HTTP_200_OK

# end point refresh token
@auth.get("/token/refresh")
@jwt_required(refresh=True)
def refresh_users_token():
    identity = get_jwt_identity()
    access = create_access_token(identity=identity)

    return jsonify({
        'access' : access
    }),HTTP_200_OK
from flask import Flask, request, jsonify, make_response, json, abort
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.exceptions import HTTPException
from functools import wraps # for token authentication
from flask_cors import CORS, cross_origin
from flask_jwt_extended import (create_access_token, create_refresh_token, get_jwt_identity, jwt_required, JWTManager,  current_user,)
import uuid
import pymysql
import jwt
import datetime
import requests #for calling external api
import logging
import sys
import urllib.request, json


app = Flask(__name__)
CORS(app=app)
app.logger.addHandler(logging.StreamHandler(sys.stdout))
app.logger.setLevel(logging.ERROR)
#app configurations
app.config['WTF_CSRF_ENABLED'] = True
app.config['SECRET_KEY'] = 'thisisfinal'

# Setup the Flask-JWT-Extended extension
app.config["JWT_SECRET_KEY"] = "thesisaretefactanditshouldbetopsecretcodethatcannotbeguessed"  # Change this!
#app.config["JWT_ACCESS_TOKEN_EXPIRES"] =  datetime.datetime().utcnow() + datetime.timedelta(hours=1) #datetime.datetime.utcnow()+datetime.timedelta(days=30)
jwt = JWTManager(app)

#SQLALCHEMY
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
#app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://bbdfb1bb4fd8ab:8cb62b1c@us-cdbr-east-06.cleardb.net/heroku_88cf6b115b887e2"
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://root:password@127.0.0.1:3306/NewsAppDB"
#pymysql.install_as_MySQLdb()
db = SQLAlchemy(app) 
ma = Marshmallow(app)
apiKey = "9c478b94ca6241648ffd727e47abf3f9"

#User table
class UserTable(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(255))
    email = db.Column(db.String(255), unique=True)
    phone = db.Column(db.String(255), unique=True)
    password=db.Column(db.String(255))
    # one-to-many collection

class FavouritesTable(db.Model):
    favId = db.Column(db.Integer, primary_key=True)
    favUrl = db.Column(db.String(255))
        
#Transaction table
class NewsTable(db.Model):
    newsId = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(2000))
    author = db.Column(db.String(2000))
    content = db.Column(db.String(2000))
    description = db.Column(db.String(2000))
    publishedDate = db.Column(db.String(255))
    url = db.Column(db.String(2000))
    urlToImage = db.Column(db.String(2000))
    isSaved = db.Column(db.Boolean())
    user_id = db.Column(db.Integer, db.ForeignKey("user_table.id"))
    source = db.Column(db.String(2000))
    #source = db.relationship("NewsSourceTable", uselist=False, backref="news")
    


#Transaction table
class NewsSourceTable(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    #news_id = db.Column(db.Integer, db.ForeignKey("news_table.news_id"))
    
class UserSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = UserTable
    
class NewsSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = NewsTable

class NewsSourceSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = NewsSourceTable
    
with app.app_context():       
    db.create_all()
    
    
#User Authorization    
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'Authorization' in request.headers:
            token = request.headers['Authorization']
        if not token:
            return jsonify({'message': 'Token is missing'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = UserTable.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

#Welcome screen
@app.route('/')
def index():
    return "Welcome to News Mobile API"

#user registation
@app.route('/signup', methods=['POST'])

def createUser():
    input = request.get_json()
    if input is None:
        raise InvalidAPIUsage("Please fill in all fields!", status_code=400)
    
    check_user = UserTable.query.filter_by(email=input['email']).first()
    if check_user:
        raise InvalidAPIUsage("User {} already exists! Please try log in.".format(check_user.email), status_code=200)
    
    check_if_phone_exists = UserTable.query.filter_by(phone=input['phone']).first()
    if check_if_phone_exists:
        raise InvalidAPIUsage("Phone number {} already exists!".format(check_if_phone_exists.phone), status_code=200)
    
    hashed_password = generate_password_hash(input['password'], method='sha256')
    new_user = UserTable(public_id=str(uuid.uuid4()), 
                         name=input['name'], 
                         email=input['email'], 
                         phone=input['phone'], 
                         password=hashed_password)
    db.session.add(new_user)
    try:
        db.session.commit()
        return make_response({'data': True,
                                     'message': 'User created successfully!',
                                     'code': '200'},  200)
    except Exception as e:
        db.session.rollback()
        raise InvalidAPIUsage(e.__str__(), status_code=400)

        
@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.id

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return UserTable.query.filter_by(id=identity).one_or_none()


class InvalidAPIUsage(Exception):
    status_code = 400

    def __init__(self, message, status_code=None, payload=None):
        super().__init__()
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        rv = dict(self.payload or ())
        rv['message'] = self.message
        rv['code'] = self.status_code.__str__()
        return rv
    

@app.errorhandler(InvalidAPIUsage)
def invalid_api_usage(e):
    return jsonify(e.to_dict()), e.status_code

@app.errorhandler(HTTPException)
def handle_exception(e):
    """Return JSON instead of HTML for HTTP errors."""
    # start with the correct headers and status code from the error
    response = e.get_response()
    # replace the body with JSON
    response.data = json.dumps({"code": e.code.__str__(),
                                "message": e.description,
                                })
    print(response.data) 
    response.content_type = "application/json"
    return response

#user login
@app.route('/login', methods=['POST'])

def login():
    email = request.form.get('email')
    password = request.form.get('password')
    
    if email and password:
        get_user = UserTable.query.filter_by(email=email).one_or_none()
        if get_user:
            if check_password_hash(get_user.password, password):
                token = create_access_token(identity=get_user, expires_delta=False)
                refresh_token = create_refresh_token(identity=get_user)
                #token = jwt.encode({'public_id':get_user.public_id,
                                   # 'exp': datetime.datetime.utcnow()+datetime.timedelta(days=30)}, 
                                   #app.config['SECRET_KEY'])
                
                return make_response({'data': {'name': get_user.name,
                                               'email': get_user.email,
                                               'phone': get_user.phone,
                                               'token': token,
                                               'refresh_token': refresh_token,
                                               'id': get_user.id
                                               },
                                      'message': 'User logged in successfully!',
                                      'code': '200'
                                      },
                                     200)
            raise InvalidAPIUsage("Username and password does not match!", status_code=200)
        raise InvalidAPIUsage("No such user!", status_code=404)
    raise InvalidAPIUsage("Username or password cannot be empty!", status_code=400)
    
#user profile update
@app.route('/user/update', methods=['PUT'])
@jwt_required()
def updateProfile():
    input = request.get_json()
    if input is None:
        raise InvalidAPIUsage("Please fill in all fields!", status_code=400)
    get_user = UserTable.query.filter_by(id=input['id']).first()
    if get_user:
        get_user.name = input['name']
        get_user.phone = input['phone']
        
        try:
            db.session.commit()
            db.session.refresh(get_user)
            userSchema = UserSchema()
            result = userSchema.dump(get_user)
            return make_response({'data': input,
                                  'message': 'User details updated successfully!',
                                  'code': '200'
                                  },
                                 200)
        except Exception as e:
            db.session.rollback()
            raise InvalidAPIUsage(e.__str__(), status_code=400)
        
    raise InvalidAPIUsage("No such user!", status_code=404)

#user password update
@app.route('/user/changepassword', methods=['PUT'])

@jwt_required()
def changePassword():
    input = request.get_json()
    if input is None:
        raise InvalidAPIUsage("Please fill in all fields!", status_code=400)
    get_user = UserTable.query.filter_by(id=input['id']).first()
    if get_user:
        if check_password_hash(get_user.password, input['currentpassword']):
            hashed_password = generate_password_hash(input['newpassword'], method='sha256')
            get_user.password = hashed_password
        
            try:
                db.session.commit()
                db.session.refresh(get_user)
                userSchema = UserSchema()
                result = userSchema.dump(get_user)
                return make_response({'data': true,
                                  'message': 'Password updated successfully!',
                                  'code': '200'
                                  },
                                 200)
            except Exception as e:
                db.session.rollback()
                raise InvalidAPIUsage(e.__str__(), status_code=400)
            
        raise InvalidAPIUsage("Current password does not match the logged in user!", status_code=400)
 
    raise InvalidAPIUsage("No such user!", status_code=404)

@app.route("/news/<country>/<category>")
@jwt_required()
def get_regional_news_list(country, category):

    url = "http://newsapi.org/v2/top-headlines?apiKey={}".format(apiKey)
    params = {'country':country, "category": category}
    
    r = requests.get(url = url, params = params)
    if r.status_code != 200:
        abort(r.status_code)
    try:
        dict = r.json()
        return make_response({'data': dict['articles'],
                          'message': '',
                          'code': '200'
                          },
                         r.status_code)
        
    except Exception as e:
        db.session.rollback()
        abort(500)
    
             
@app.route("/news/search/<text>")
@jwt_required()
def get_news_based_on_search(text):
    url = "http://newsapi.org/v2/everything?apiKey={}".format(apiKey)
    params = {'q': text }
    r = requests.get(url = url, params = params)
    if r.status_code != 200:
        abort(r.status_code)
    try:
        dict = r.json()
        return make_response({'data': dict['articles'],
                          'message': '',
                          'code': '200'
                          },
                         200)
        
    except Exception as e:
        db.session.rollback()
        abort(500)

if __name__ == "main":
    app.debug(debug=True)
    


# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""
import json
from array import array
from datetime import datetime, timezone, timedelta

from functools import wraps

from flask import request
from flask_restx import Api, Resource, fields

import jwt

from .models import db, Users, JWTTokenBlocklist
from .config import BaseConfig
import requests

from .sqlite import db_start,db_create_company,db_get_all_companies,db_add_notification_in_table,db_get_all_data,db_get_all_locations

rest_api = Api(version="1.0", title="Users API")



class Obj:
    def __init__(self, x, y):
        self.x = x
        self.y = y




class Obj2:
    def __init__(self, date, positive,negative):
        self.date =  date
        self.positive = positive
        self.negative = negative

class Locations:
    def __init__(self, name, address):
        self.name = name
        self.address = address

class ObjGraph:
    def __init__(self, emotion, value):
        self.emotion = emotion
        self.value = value

"""
    Flask-Restx models for api request and response data
"""

signup_model = rest_api.model('SignUpModel', {"username": fields.String(required=True, min_length=2, max_length=32),
                                              "email": fields.String(required=True, min_length=4, max_length=64),
                                              "password": fields.String(required=True, min_length=4, max_length=16)
                                              })

login_model = rest_api.model('LoginModel', {"email": fields.String(required=True, min_length=4, max_length=64),
                                            "password": fields.String(required=True, min_length=4, max_length=16)
                                            })

user_edit_model = rest_api.model('UserEditModel', {"userID": fields.String(required=True, min_length=1, max_length=32),
                                                   "username": fields.String(required=True, min_length=2, max_length=32),
                                                   "email": fields.String(required=True, min_length=4, max_length=64)
                                                   })


"""
   Helper function for JWT token required
"""

def token_required(f):

    @wraps(f)
    def decorator(*args, **kwargs):

        token = None

        if "authorization" in request.headers:
            token = request.headers["authorization"]

        if not token:
            return {"success": False, "msg": "Valid JWT token is missing"}, 400

        try:
            data = jwt.decode(token, BaseConfig.SECRET_KEY, algorithms=["HS256"])
            current_user = Users.get_by_email(data["email"])

            if not current_user:
                return {"success": False,
                        "msg": "Sorry. Wrong auth token. This user does not exist."}, 400

            token_expired = db.session.query(JWTTokenBlocklist.id).filter_by(jwt_token=token).scalar()

            if token_expired is not None:
                return {"success": False, "msg": "Token revoked."}, 400

            if not current_user.check_jwt_auth_active():
                return {"success": False, "msg": "Token expired."}, 400

        except:
            return {"success": False, "msg": "Token is invalid"}, 400

        return f(current_user, *args, **kwargs)

    return decorator


"""
    Flask-Restx routes
"""


@rest_api.route('/api/users/register')
class Register(Resource):
    """
       Creates a new user by taking 'signup_model' input
    """

    @rest_api.expect(signup_model, validate=True)
    def post(self):

        req_data = request.get_json()

        _username = req_data.get("username")
        _email = req_data.get("email")
        _password = req_data.get("password")

        user_exists = Users.get_by_email(_email)
        if user_exists:
            return {"success": False,
                    "msg": "Email already taken"}, 400

        new_user = Users(username=_username, email=_email)

        new_user.set_password(_password)
        new_user.save()

        return {"success": True,
                "userID": new_user.id,
                "msg": "The user was successfully registered"}, 200

"""
@rest_api.route('/api/users/login')
class Login(Resource):
"""

     #  Login user by taking 'login_model' input and return JWT token

"""
    @rest_api.expect(login_model, validate=True)
    def post(self):

        req_data = request.get_json()

        _email = req_data.get("email")
        _password = req_data.get("password")

        user_exists = Users.get_by_email(_email)

        if not user_exists:
            return {"success": False,
                    "msg": "This email does not exist."}, 400

        if not user_exists.check_password(_password):
            return {"success": False,
                    "msg": "Wrong credentials."}, 400

        # create access token uwing JWT
        token = jwt.encode({'email': _email, 'exp': datetime.utcnow() + timedelta(minutes=30)}, BaseConfig.SECRET_KEY)

        user_exists.set_jwt_auth_active(True)
        user_exists.save()

        return {"success": True,
                "token": token,
                "user": user_exists.toJSON()}, 200

"""
@rest_api.route('/api/users/edit')
class EditUser(Resource):
    """
       Edits User's username or password or both using 'user_edit_model' input
    """

    @rest_api.expect(user_edit_model)
    @token_required
    def post(self, current_user):

        req_data = request.get_json()

        _new_username = req_data.get("username")
        _new_email = req_data.get("email")

        if _new_username:
            self.update_username(_new_username)

        if _new_email:
            self.update_email(_new_email)

        self.save()

        return {"success": True}, 200


@rest_api.route('/api/users/logout')
class LogoutUser(Resource):
    """
       Logs out User using 'logout_model' input
    """

    @token_required
    def post(self, current_user):

        _jwt_token = request.headers["authorization"]

        jwt_block = JWTTokenBlocklist(jwt_token=_jwt_token, created_at=datetime.now(timezone.utc))
        jwt_block.save()

        self.set_jwt_auth_active(False)
        self.save()

        return {"success": True}, 200


@rest_api.route('/api/sessions/oauth/github/')
class GitHubLogin(Resource):
    def get(self):
        code = request.args.get('code')
        client_id = BaseConfig.GITHUB_CLIENT_ID
        client_secret = BaseConfig.GITHUB_CLIENT_SECRET
        root_url = 'https://github.com/login/oauth/access_token'

        params = { 'client_id': client_id, 'client_secret': client_secret, 'code': code }

        data = requests.post(root_url, params=params, headers={
            'Content-Type': 'application/x-www-form-urlencoded',
        })

        response = data._content.decode('utf-8')
        access_token = response.split('&')[0].split('=')[1]

        user_data = requests.get('https://api.github.com/user', headers={
            "Authorization": "Bearer " + access_token
        }).json()
        
        user_exists = Users.get_by_username(user_data['login'])
        if user_exists:
            user = user_exists
        else:
            try:
                user = Users(username=user_data['login'], email=user_data['email'])
                user.save()
            except:
                user = Users(username=user_data['login'])
                user.save()
        
        user_json = user.toJSON()

        token = jwt.encode({"username": user_json['username'], 'exp': datetime.utcnow() + timedelta(minutes=30)}, BaseConfig.SECRET_KEY)
        user.set_jwt_auth_active(True)
        user.save()

        return {"success": True,
                "user": {
                    "_id": user_json['_id'],
                    "email": user_json['email'],
                    "username": user_json['username'],
                    "token": token,
                }}, 200





@rest_api.route('/api/users/login')
class Login(Resource):
    """
       Login user by taking 'login_model' input and return JWT token
    """

    @rest_api.expect(login_model, validate=False)
    def post(self):
        login_exists=False
        password_correct = False


        req_data = request.get_json()

        _login = req_data.get("login")
        _password = req_data.get("password")


        user_exists =db_get_all_companies()

        _email=0
        _company_name = 0
        _info = 0
        _locations = 0
        _contacts = 0

        for obj in user_exists:
            if obj[2] == _login:
                login_exists = True
                if obj[3]==_password:
                    password_correct = True
                    _email= obj[4]
                    _company_name= obj[1]
                    _info = obj[5]
                    _locations = obj[6]
                    _contacts = obj[7]




        locations = json.loads(_locations.replace("'", "\""))
        # print(locations)
        # print(type(locations))
        if not login_exists:
            return {"success": False,
                    "msg": "This login does not exist."}, 400

        if not password_correct:
            return {"success": False,
                    "msg": "Wrong password"}, 400

        # create access token uwing JWT
      #  token = jwt.encode({'email': _email, 'exp': datetime.utcnow() + timedelta(minutes=30)}, BaseConfig.SECRET_KEY)

     #   user_exists.set_jwt_auth_active(True)
      #  user_exists.save()


        # objs_list=[]
        #
        # for k, v in dict_sample.items():
        #     objs_list.append(ObjGraph(k, v))
        #
        # j = 0
        # for i in objs_list:
        #     objs_list[j] = i.__dict__
        #     j = j + 1
        print(_company_name)
        aa = db_get_all_locations(_company_name)

        objs_list = []

        for i in aa:
            objs_list.append(Locations(name=i[2], address=i[3]))

        j = 0
        for i in objs_list:
            objs_list[j] = i.__dict__
            j = j + 1

        print(aa)


        return {"success": True,"email": _email,"company_name": _company_name,"info":_info,"locations":objs_list,"contacts": _contacts }, 200


@rest_api.route('/api/data/emotions')
class GetEmotions(Resource):
    def post(self):


        email_exists=False
        password_correct = False


        req_data = request.get_json()

        _company = req_data.get("company")

      #  db_add_notification_in_table(_company)

        user_exists =db_get_all_data(_company)


        x_counts = {}
        for t in user_exists:
            print(type(t))
            if t[1] in x_counts:
                x_counts[t[1]] += 1
            else:
                x_counts[t[1]] = 1

        objs_list = []

        for i, item in enumerate(x_counts):
            objs_list.append(Obj(item, x_counts[item]))



        j=0
        for i in objs_list:
            objs_list[j]=i.__dict__
            j=j+1


        return  objs_list, 200





@rest_api.route('/api/data/graphs')
class GetGraphs(Resource):
    def post(self):


        email_exists=False
        password_correct = False


        req_data = request.get_json()

        _company = req_data.get("company")
        _startDate = datetime.strptime(req_data.get("startDate"), '%d/%m/%Y')
        _endDate = datetime.strptime(req_data.get("endDate"), '%d/%m/%Y')

       # db_add_notification_in_table(_company)

        user_exists =db_get_all_data(_company)


        x_counts = {}
        for t in user_exists:

            if t[1] in x_counts:
                x_counts[t[1]] += 1
            else:
                x_counts[t[1]] = 1

        selected_list = []
        for t in user_exists:
            if((_startDate<=datetime.strptime(t[1], '%d/%m/%Y'))and(_endDate>=datetime.strptime(t[1], '%d/%m/%Y'))):
                selected_list.append(t)


        dict_sample = {
            "angry": 0,
            "disgust": 0,
            "fear": 0,
            'happy': 0,
            'sad': 0,
            'surprise': 0,
            'neutral': 0
        }

        for t in selected_list:
            print(t[3])
            dictionary= json.loads(t[3].replace("'", "\""))
            print(dictionary)
            for k, v in dictionary.items():
                dict_sample[k]+=v

        objs_list=[]

        for k, v in dict_sample.items():
            objs_list.append(ObjGraph(k, v))

        j = 0
        for i in objs_list:
            objs_list[j] = i.__dict__
            j = j + 1


        return  objs_list, 200





@rest_api.route('/api/data/graphs/location')
class GetGraphsLocation(Resource):
    def post(self):


        email_exists=False
        password_correct = False


        req_data = request.get_json()

        _company = req_data.get("company")
        _location = req_data.get("location")
        _startDate = datetime.strptime(req_data.get("startDate"), '%d/%m/%Y')
        _endDate = datetime.strptime(req_data.get("endDate"), '%d/%m/%Y')

       # db_add_notification_in_table(_company)

        user_exists =db_get_all_data(_company)


        x_counts = {}
        for t in user_exists:

            if t[1] in x_counts:
                x_counts[t[1]] += 1
            else:
                x_counts[t[1]] = 1

        selected_list = []
        for t in user_exists:
            if((_startDate<=datetime.strptime(t[1], '%d/%m/%Y'))and(_endDate>=datetime.strptime(t[1], '%d/%m/%Y'))):
                selected_list.append(t)


        dict_sample = {
            "angry": 0,
            "disgust": 0,
            "fear": 0,
            'happy': 0,
            'sad': 0,
            'surprise': 0,
            'neutral': 0
        }

        for t in selected_list:
            # print(t[3])

            if t[6] == _location:
                dictionary= json.loads(t[3].replace("'", "\""))
                # print(dictionary)
                for k, v in dictionary.items():
                    dict_sample[k]+=v

        objs_list=[]

        for k, v in dict_sample.items():
            objs_list.append(ObjGraph(k, v))

        j = 0
        for i in objs_list:
            objs_list[j] = i.__dict__
            j = j + 1


        return  objs_list, 200




@rest_api.route('/api/data/graphs/discrete')
class GetEmotions(Resource):
    def post(self):
        positive=0
        negative=0


        email_exists=False
        password_correct = False


        req_data = request.get_json()

        _company = req_data.get("company")

      #  db_add_notification_in_table(_company)

        user_exists =db_get_all_data(_company)








# словарь дата - количество посетителей
        x_counts = {}
        for t in user_exists:
            print(type(t))

            dictionary = json.loads(t[3].replace("'", "\""))
            max_key = max(dictionary, key=dictionary.get)


            if t[1] in x_counts:
                if (max_key == 'happy'):
                    x_counts[t[1]][0] += 1
                else:
                    if (max_key != 'surprise'):

                        x_counts[t[1]][1] += 1


            else:
                x_counts[t[1]] =[0,0]

                if (max_key == 'happy'):

                    x_counts[t[1]][0] += 1
                else:
                    if (max_key != 'surprise'):

                        x_counts[t[1]][1] += 1

        objs_list = []

        for i, item in enumerate(x_counts):
            objs_list.append(Obj2(item, x_counts[item][0],x_counts[item][1]))



        j=0
        for i in objs_list:
            objs_list[j]=i.__dict__
            j=j+1


        return  objs_list, 200


@rest_api.route('/api/data/graphs/discrete/sex')
class GetEmotions(Resource):
    def post(self):
        positive=0
        negative=0


        email_exists=False
        password_correct = False


        req_data = request.get_json()

        _company = req_data.get("company")

        _sex = req_data.get("sex")
      #  db_add_notification_in_table(_company)

        user_exists =db_get_all_data(_company)

        dict_sample1 = {
            "angry": 0,
            "disgust": 0,
            "fear": 0,
            'happy': 0,
            'sad': 0,
            'surprise': 0,
            'neutral': 0
        }

        dict_sample2 = {
            "angry": 0,
            "disgust": 0,
            "fear": 0,
            'happy': 0,
            'sad': 0,
            'surprise': 0,
            'neutral': 0
        }


        for t in user_exists:

            if (str(t[4]) == '1'):
                dictionary = json.loads(t[3].replace("'", "\""))
                max_key = max(dictionary, key=dictionary.get)
                dict_sample1[max_key] += 1
            else:
                if (str(t[4]) == '0'):
                    dictionary = json.loads(t[3].replace("'", "\""))
                    max_key = max(dictionary, key=dictionary.get)
                    dict_sample2[max_key] += 1

        objs_list = [0,0]

        objs_list1 = []
        objs_list2 = []


        for k, v in dict_sample1.items():
            objs_list1.append(ObjGraph(k, v))

        j = 0
        for i in objs_list1:
            objs_list1[j] = i.__dict__
            j = j + 1


        for k, v in dict_sample2.items():
            objs_list2.append(ObjGraph(k, v))

        j = 0
        for i in objs_list2:
            objs_list2[j] = i.__dict__
            j = j + 1

        objs_list[0]=objs_list1
        objs_list[1] = objs_list1

        return  objs_list, 200
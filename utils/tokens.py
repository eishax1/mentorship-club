import jwt
from flask import request, make_response , jsonify, current_app
import datetime
from flask import current_app
from pymongo import MongoClient

#mongosetup
client = MongoClient("mongodb://127.0.0.1:27017")
db = client.Mentorship
blacklist = db.blacklist

def create_token(user):
    return jwt.encode(
        {
            'user_id': str(user['_id']),
            'admin': user['admin'],
            'role': user['role'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        },
        current_app.config['SECRET_KEY'],
        algorithm="HS256"
    )

def token_is_blacklisted(token):
    return blacklist.find_one({'token': token}) is not None

def decode_token():
    """Decode the JWT token and handle common errors."""
    token = request.headers.get('x-access-token')
    if not token:
        return None, make_response(jsonify({'message': 'Authentication required'}), 401)

    try:
        data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms="HS256")
        #Check if the token is blacklisted
        if token_is_blacklisted(token):
            return None, make_response(jsonify({'message': 'Token is blacklisted'}), 403)

        return data, None  
    except jwt.ExpiredSignatureError:
        return None, make_response(jsonify({'message': 'Token has expired'}), 401)
    except jwt.InvalidTokenError:
        return None, make_response(jsonify({'message': 'Invalid token'}), 401)

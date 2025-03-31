from flask import Flask, make_response, jsonify, request, session
import bcrypt
from bson.objectid import ObjectId
import datetime

from pymongo import MongoClient
from utils.tokens import create_token
from decorators.mentor_admin import admin_or_mentor_required

from decorators.admin import admin_required
from flask_cors import CORS

# App Configuration
app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'mysecret'

# MongoDB Setup
client = MongoClient("mongodb://127.0.0.1:27017")
db = client.Mentorship
file_collection = db.uploads
announcement_collection= db.announcements
users = db.user
blacklist = db.blacklist

#-------------------------------------Authentication routes---------------------------------------------

@app.route('/api/v1.0/login', methods=['GET']) 
def login():
    if 'user_id' in session:
        return make_response(jsonify({'message': 'You are already logged in. Please log out before attempting to log in again.'}), 409)
    
    auth = request.authorization
    if auth:
        user = users.find_one({'username': auth.username})
        if user is not None:
            if bcrypt.checkpw(bytes(auth.password, 'UTF-8'), user["password"]):
            
                token = create_token(user)
                session.clear()
                # Set the session to indicate the user is logged in
                session['user_id'] = str(user['_id'])
                return make_response(jsonify({'message': f'Welcome back, {user["username"]}! You have successfully logged in.', 'token created': token, 'role': user.get("role", "mentee")}), 201)# Return the role
            else:
                return make_response(jsonify({'message': 'Invalid password. Please try again.'}), 401)
        else:
            return make_response(jsonify({'message': 'No user found with this username. Please check and try again.'}), 401)
    
    return make_response(jsonify({'message': 'Authentication is required to access this resource.'}), 401)

@app.route('/logout', methods=["GET"])
def logout():
    token = request.headers.get('x-access-token')
    if token:
        # Add the token to the blacklist
        blacklist.insert_one({'token': token})
    # Clear the entire session
    session.clear()
    return make_response(jsonify({'message': 'You have successfully logged out. See you next time!'}), 200)


#-----------------------admin routes------------------

@app.route('/api/v1.0/users', methods=['POST'])
@admin_required
def create_user():
    # Get the data from the request body
    data = request.get_json()
    
    # Extract fields from the request body
    name = data.get('name')
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    role = data.get('role', 'mentee')  # Default role is 'mentee'
    
    # Admin logic: If role is 'admin', set admin to True, else False
    admin = True if role == 'admin' else False

    # Hash the password before storing it
    hashed_password = bcrypt.hashpw(bytes(password, 'UTF-8'), bcrypt.gensalt())

    # Create user object to insert into the database
    new_user = {
        'name': name,
        'username': username,
        'password': hashed_password,
        'email': email,
        'admin': admin,  # Set admin based on role
        'role': role,
    }

    # Insert the user into the database
    users.insert_one(new_user)

    # Return success response
    return make_response(jsonify({'message': f'User {username} created successfully!'}), 201)

@app.route('/api/v1.0/announcements', methods=['POST'])
@admin_required
def create_announcement():
    data = request.get_json()
    title = data.get('title')
    content = data.get('content')
    if not title or not content:
        return make_response(jsonify({'message': 'Title and content are required.'}), 400)

    announcement = {
        'title': title,
        'content': content,
        'created_at': datetime.datetime.utcnow()
    }

    announcement_collection.insert_one(announcement)
    return make_response(jsonify({'message': 'Announcement created successfully.'}), 201)

#delete announcements
@app.route('/api/v1.0/announcements/<announcement_id>', methods=['DELETE'])
@admin_required
def delete_announcement(announcement_id):
    result = announcement_collection.delete_one({'_id': ObjectId(announcement_id)})
    if result.deleted_count > 0:
        return make_response(jsonify({'message': 'Announcement deleted successfully.'}), 200)
    return make_response(jsonify({'message': 'Announcement not found.'}), 404)


#------------public routes---------------
#all announcements
@app.route('/api/v1.0/announcements', methods=['GET'])
def get_announcements():
    announcements = announcement_collection.find()
    announcements_list = [{"title": a['title'], "content": a['content'], "created_at": a['created_at']} for a in announcements]
    return make_response(jsonify(announcements_list), 200)

#get announcements by id
@app.route('/api/v1.0/announcements/<announcement_id>', methods=['GET'])
def get_announcement(announcement_id):
    announcement = announcement_collection.find_one({'_id': ObjectId(announcement_id)})
    if announcement:
        return make_response(jsonify({'title': announcement['title'], 'content': announcement['content'], 'created_at': announcement['created_at']}), 200)
    return make_response(jsonify({'message': 'Announcement not found.'}), 404)



if __name__ == "__main__":
    app.run(debug=True)  

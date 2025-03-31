from pymongo import MongoClient
import bcrypt #for password hashing 

client = MongoClient("mongodb://127.0.0.1:27017")
db = client.Mentorship      
users = db.user        

user_list = [
          { 
            "name" : "Eisha Sultana",
            "username" : "eisha",  
            "password" : b"6737610",
            "email" : "Eisha_Sultana-ES@ulster.ac.uk",
            "admin" : True,
            "role" : "mentor"
          },
          { 
            "name" : "Mushahid Mutin Sadi",
            "username" : "sadi",  
            "password" : b"123",
            "email" : "Sadi-MM@ulster.ac.uk",
            "admin" : False,
            "role" : "mentor"
          },
          { 
            "name" : "Sheikh Lam Yea Marzan",
            "username" : "marzan",  
            "password" : b"123",
            "email" : "Marzan-SLY@ulster.ac.uk",
            "admin" : False,
            "role" : "mentee"
          }
          ]
for new_user in user_list:
      new_user["password"] = bcrypt.hashpw(new_user["password"], bcrypt.gensalt())
      users.insert_one(new_user)

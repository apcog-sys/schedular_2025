# py -3 -m pip install Flask  (install libraries in python 3.9 syntax)

#from distutils.log import error

from flask import Flask, render_template, jsonify, request,redirect
from flask_cors import CORS 
from flask import *
import json
import random
import datetime 
from datetime import datetime, timedelta
import pymysql
from db_operations import * 


# global variables
mydb = pymysql.connect(
  host="localhost",
  user="root",
  password="root",
  db="medicube"
)

db_name = 'event_scheduler2025'

try:
    mycursor = mydb.cursor()
    print("DB connected")
except:
    print("DB not connected")
new_session_id=0


app = Flask(__name__)
#CORS(app)
CORS(app, resources={r"/*": {"origins": "*"}})

######################################################### TESTING ############################################################

from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import pymysql


app.config['JWT_SECRET_KEY'] = 'supersecretkey'  # Change this in production
jwt = JWTManager(app)

USERS = {
    "admin_user": {"password": "adminpass", "role": "admin"},
    "approver_user": {"password": "approverpass", "role": "approver"},
    "normal_user": {"password": "userpass", "role": "user"}
}



from functools import wraps  # Add this at the top
import logging
logging.basicConfig(level=logging.DEBUG)


def role_required(allowed_roles):
    print("Decorator called")
    def decorator(func):
        print("Inside decorator")
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                print("Inside wrapper")
                # Simulate JWT identity for testing
                print("Authorization header:", request.headers.get('Authorization'))
                getuserrole = get_jwt_identity()
                print("User Role from JWT:", getuserrole)
                user = {"role": getuserrole}
                print(f"User: {user}")
                if not user or user["role"] not in allowed_roles:
                    print("Access denied")
                    return jsonify({"error": "Access denied"}), 403
                print("Access granted")
                return func(*args, **kwargs)
            except Exception as e:
                print(f"Error in role_required: {str(e)}")
                return jsonify({"error": str(e)}), 500
        return wrapper
    return decorator


@app.route('/test', methods=['GET'])
@role_required(["admin"])
def test_route():
    return jsonify({"message": "Access granted"})

######################################################### TESTING ############################################################

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    user = USERS.get(username)
    if user and user["password"] == password:
        token = create_access_token(identity={"username": username, "role": user["role"]})
        return jsonify({"token": token, "role": user["role"]})
    
    return jsonify({"error": "Invalid credentials"}), 401


# Create an Entity (Admin Only)
@app.route('/new_test', methods=['POST'])
@jwt_required()
@role_required(["admin"])  # Ensure the user is an admin
def create_entity():
    data = request.get_json()
    if not data or "entity_name" not in data or "entity_type" not in data:
        return jsonify({"error": "Missing required fields"}), 422  # Detailed error message
    print("Received Data:", data)
    try:
        connection = pymysql.connect(
            host="localhost",
            user="root",
            password="root",
            db="event_scheduler2025"
        )
        cursor = connection.cursor()
        sql = "INSERT INTO entity (entity_name, entity_type, entry_status) VALUES (%s, %s, %s)"
        cursor.execute(sql, (data["entity_name"], data["entity_type"], "active"))
        connection.commit()
        return jsonify({"message": "Entity created successfully"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        connection.close()




@app.route('/alive')
def test():
    return jsonify({"ack":"hello,  welcome"}) 

@app.route('/')
def login_page():
    return render_template('login.html') 
    
@app.route('/app')
def home_page():
    return render_template('index.html') 
@app.route('/app2')
def home_page2():
    return render_template('test.html')

@app.route('/options', methods=['POST'])
def get_helper_data():
    data = request.get_json()  # Use request.get_json() instead of json.loads(request.data)
    print("Received Data:", data)

    f=open('config/new/get_DB_data.json');  json_data = json.load(f)
    print("db name: ",json_data)
    data = json.loads(request.data); print(data)
    
    try:
        myresult=get_data(json_data['db_name'],json_data[data['tab']][data['type']], data['qry']['select_fields'],data['qry']['where_data']) 
        print(myresult);    return jsonify(myresult)
    except Exception as e:
        print("Error:", e)
        return jsonify({"error": str(e)}), 500
        
@app.route('/get_user_tabs',methods=['POST','GET'])
def get_user_tabs():
    data = request.data 
    y = json.loads(data) 
    print(y['role'])    # the result is a Python dictionary:
    f=open('config/new/user_tabs.json')
    tab_data = json.load(f)
    if (y['role']=="Admin"):
        response=tab_data['Admin']
    elif (y['role']=="User"):
        response=tab_data['User']
    elif (y['role']=="Finance_admin"):
        response=tab_data['Finance_admin']
    elif (y['role']=="Campaign_admin"):
        response=tab_data['Campaign_admin']
    else:
        response=jsonify("role not defined")
    print(response)
    return jsonify(response)


######################################################  ENTITY  APIs  ####################################################################

@app.route('/entity/new', methods=['POST'])
def insert_entity():
    data = request.json
    f=open('config/new/get_DB_data.json');  json_data = json.load(f)
    data = request.json
    print(data)
    #details = get_token_details(data.token_value,db_name)
    #print(details)
    required_columns = ['entity_id', 'entity_name', 'entity_type', 'created_at', 'updated_at', 'entry_status', 'archive']
    
    # Check for missing columns
    missing_columns = [col for col in required_columns if col not in data.get("qry")]
    print(3)
    success, message = insert_ignore(json_data['db_name'],json_data['general']['entity_table_name'], data.get("qry"))
    print(4)
    if success:
        return jsonify({'message': message}), 201
    else:
        return jsonify({'error': message}), 400

#new
@app.route('/entity/new1', methods=['POST'])
def entity_new1():
    f=open('config/new/get_DB_data.json');  json_data = json.load(f)
    print("db name: ",json_data)
    data = request.json
    required_columns = ['entity_id', 'entity_name', 'entity_type', 'created_at', 'updated_at', 'entry_status', 'archive']
    
    # Check for missing columns
    missing_columns = [col for col in required_columns if col not in data]
    if missing_columns:
        return jsonify({'error': f"Missing columns: {', '.join(missing_columns)}"}), 400
    
    # Insert data into the entity table
    success, message = insert_ignore(json_data['general']['entity_table_name'], data, json_data['db_name'])
    
    if success:
        return jsonify({'message': message}), 201
    else:
        return jsonify({'error': message}), 400

# Update Entry API
@app.route('/entity/modifications', methods=['PUT'])
def update_entry_api():
    # validate the qry, for assuring all the required fields are present. 
    f=open('config/new/get_DB_data.json');  json_data = json.load(f)
    data = request.json
    update_data = data.get("qry")
    where_data = {"entity_id":data.get('entity_id')}
    print(">>",update_data,where_data) 

    if not update_data or not where_data:
        return jsonify({"error": "Missing table_name, update_data or where_data"}), 400
    success = update_entry(json_data['db_name'],json_data['general']['entity_table_name'], update_data,where_data,)
    if success:
        return jsonify({"message": "Entry updated successfully"}), 200
    else:
        return jsonify({"error": "Failed to update entry"}), 500

# Delete Entry API
@app.route('/entity', methods=['DELETE'])
def delete_entry_api():
    f=open('config/new/get_DB_data.json');  json_data = json.load(f)
    print("db name: ",json_data['db_name'])
    data = json.loads(request.data); entity_id = data['entity_id']
    print(data)

    if not entity_id:
        return jsonify({"error": "Missing  entity_id"}), 400

    success = delete_entry(json_data['db_name'],json_data['general']['entity_table_name'], {"entity_id":entity_id} )
    if success:
        return jsonify({"message": "Entry deleted successfully"}), 200
    else:
        return jsonify({"error": "Failed to delete entry"}), 500

@app.route('/entity/list_details',methods=['POST','GET'])
def entity_get_data():
    json_data={};  
    f=open('config/new/get_DB_data.json');  json_data = json.load(f)
    print("db name: ",json_data)
    data = json.loads(request.data); print(data)
    
    try:
        myresult=get_data(json_data['db_name'],json_data['general']['entity_table_name'], data['qry']['select_fields'],data['qry']['where_data']) 
        print(myresult)
        if(data['qry']['where_data']=={}):
            return jsonify([myresult])
        else:
            return jsonify([myresult])
     
    except Exception as e:
        print(">>8")
        print("Error:", e)
        return jsonify({"error": str(e)}), 500
    
######################################################  RESOURCE  APIs  ####################################################################

@app.route('/resource/new', methods=['POST'])
def resource_new():
    data = request.json
    f=open('config/new/get_DB_data.json');  json_data = json.load(f)
    data = request.json
    print(data)
    
    # Insert data into the entity table
    success, message = insert_ignore(json_data['db_name'],json_data[data['tab']][data['type']], data.get("qry"))
    
    if success:
        return jsonify({'message': message}), 201
    else:
        return jsonify({'error': message}), 400

@app.route('/resource/list_details', methods=['POST', 'GET'])
def resource_list():
    f=open('config/new/get_DB_data.json');  json_data = json.load(f)
    print("db name: ",json_data)
    data = json.loads(request.data); 
    print("data >>", json_data['db_name'],json_data[data['tab']][data['type']], data['qry']['select_fields'],data['qry']['where_data'])
    
    try:
        myresult=get_data(json_data['db_name'],json_data[data['tab']][data['type']], data['qry']['select_fields'],data['qry']['where_data']) 
        print(myresult)
        return jsonify([myresult])
     
    except Exception as e:
        print("Error:", e)
        return jsonify({"error": str(e)}), 500

# Update Resource API
@app.route('/resource/modifications', methods=['PUT'])
def resource_update():
    # validate the qry, for assuring all the required fields are present. 
    f=open('config/new/get_DB_data.json');  json_data = json.load(f)
    data = request.json
    qry = data.get("qry")
    update_data =qry.get("update")
    where_data = {"resource_id":data.get('resource_id')}
    print(">>",update_data) 
    print(">>",where_data) 

    if not update_data or not where_data:
        return jsonify({"error": "Missing table_name, update_data or where_data"}), 400
    success = update_entry(json_data['db_name'],json_data[data['tab']][data['type']], update_data,where_data,)
    if success:
        return jsonify({"message": "Entry updated successfully"}), 200
    else:
        return jsonify({"error": "Failed to update entry"}), 500

# Delete Entry API
@app.route('/resource', methods=['DELETE'])
def resoure_delete():
    f=open('config/new/get_DB_data.json');  json_data = json.load(f)
    data = request.json
    print("data :",data)
    where_data = data.get('qry', {}).get('where_data', {})
    print("where_data :",where_data)
    
    success = delete_entry(json_data['db_name'],json_data[data['tab']][data['type']], where_data )
    if success:
        return jsonify({"message": "Entry deleted successfully"}), 200
    else:
        return jsonify({"error": "Failed to delete entry"}), 500

######################################################  EVENT  APIs  ####################################################################

#new
@app.route('/event/new', methods=['POST'])
def event_new():
    data = request.json
    f=open('config/new/get_DB_data.json');  json_data = json.load(f)
    data = request.json
    print(data)
   
    # Insert data into the entity table
    success, message = insert_ignore(json_data['db_name'],json_data['general']['event_table_name'], data.get("qry"))
    
    if success:
        return jsonify({'message': message}), 201
    else:
        return jsonify({'error': message}), 400

# List
@app.route('/event/list_details', methods=['POST', 'GET'])
def event_list():
    print("**************************************************")
    f=open('config/new/get_DB_data.json');  json_data = json.load(f)
    print("db name: ",json_data['db_name'])
    data = json.loads(request.data); print(data)
   
    where_data = {"name": "python bootcamp"}
    # "venue.city": "Manipal"
    data['qry']['select_fields']=["venue.city","name","category"]
    try:
        #myresult=get_data(json_data['db_name'],json_data['general']['event_table_name'], data['qry']['select_fields'],data['qry']['where_data'])
        print(json_data['db_name'],json_data['general']['event_table_name'], data['qry']['select_fields'],where_data)
        myresult=get_data(json_data['db_name'],json_data['general']['event_table_name'], data['qry']['select_fields'],where_data) 
        print(myresult)
        if(data['qry']['where_data']=={}):
            return jsonify([myresult])
        else:
            return jsonify([myresult])
     
    except Exception as e:
        print("Error:", e)
        return jsonify({"error": str(e)}), 500

# Delete 
@app.route('/event', methods=['DELETE'])
def event_delete():
    f=open('config/new/get_DB_data.json');  json_data = json.load(f)
    print("db name: ",json_data['db_name'])
    data = request.json
    where_data = data.get('where_data')
    
    db_name = 'event_scheduler2025'
    success = delete_entry(json_data['general']['event_table_name'], where_data,json_data['db_name'])
    if success:
        return jsonify({"message": "Entry deleted successfully"}), 200
    else:
        return jsonify({"error": "Failed to delete entry"}), 500

# Update 
@app.route('/event/modifications', methods=['PUT'])
def event_update():
    f=open('config/new/get_DB_data.json');  json_data = json.load(f)
    print("db name: ",json_data['db_name'])
    data = request.json
    update_data = data.get("qry")
    where_data = {"event_id":data.get('event_id')}
    print(">>",update_data,where_data) 

    if not update_data or not where_data:
        return jsonify({"error": "Missing table_name, update_data or where_data"}), 400
    success = update_entry(json_data['db_name'],json_data['general']['event_table_name'], update_data,where_data,)
    if success:
        return jsonify({"message": "Entry updated successfully"}), 200
    else:
        return jsonify({"error": "Failed to update entry"}), 500
   

######################################################  ALERTS  APIs  ####################################################################

#new
@app.route('/alert/new', methods=['POST'])
def alert_new():
    f=open('config/new/get_DB_data.json');  json_data = json.load(f)
    print("db name: ",json_data)
    data = request.json
    required_columns = ["event_id", "target_category", "message_id", "alert_datetime"]
    
    # Check for missing columns
    missing_columns = [col for col in required_columns if col not in data.get("qry")]
    if missing_columns:
        return jsonify({'error': f"Missing columns: {', '.join(missing_columns)}"}), 400
    
    # Insert data into the entity table
    success, message = insert_ignore(json_data['db_name'],json_data['general']['alert_table_name'],data.get("qry"))
    
    if success:
        return jsonify({'message': message}), 201
    else:
        return jsonify({'error': message}), 400

# List
@app.route('/alert/list_details', methods=['POST', 'GET'])
def alert_list():
    f=open('config/new/get_DB_data.json');  json_data = json.load(f)
    print("db name: ",json_data)
    data = json.loads(request.data); print(data)
    
    try:
        myresult=get_data(json_data['db_name'],json_data['general']['alert_table_name'], data['qry']['select_fields'],data['qry']['where_data']) 
        print(myresult)
        if(data['qry']['where_data']=={}):
            return jsonify([myresult])
        else:
            return jsonify([myresult])
     
    except Exception as e:
        print("Error:", e)
        return jsonify({"error": str(e)}), 500

# Update 
@app.route('/alert/modifications', methods=['PUT'])
def alert_update():
    f=open('config/new/get_DB_data.json');  json_data = json.load(f)
    print("db name: ",json_data['db_name'])
    data = request.json
    update_data = data.get("qry")
    where_data = {"alert_id":data.get('alert_id')}
    print(">>",update_data,where_data) 

    if not update_data or not where_data:
        return jsonify({"error": "Missing table_name, update_data or where_data"}), 400
    success = update_entry(json_data['db_name'],json_data['general']['alert_table_name'], update_data,where_data,)
    if success:
        return jsonify({"message": "Entry updated successfully"}), 200
    else:
        return jsonify({"error": "Failed to update entry"}), 500

# Delete 
@app.route('/alert', methods=['DELETE'])
def alert_delete():
    f=open('config/new/get_DB_data.json');  json_data = json.load(f)
    print("db name: ",json_data['db_name'])
    data = request.json
    where_data = data.get('where_data')
    
    db_name = 'event_scheduler2025'
    success = delete_entry(json_data['general']['alert_table_name'], where_data,json_data['db_name'])
    if success:
        return jsonify({"message": "Entry deleted successfully"}), 200
    else:
        return jsonify({"error": "Failed to delete entry"}), 500

######################################################  MESSAGE  APIs  ####################################################################

#new
@app.route('/message/new', methods=['POST'])
def message_new():
    f=open('config/new/get_DB_data.json');  json_data = json.load(f)
    print("db name: ",json_data)
    data = json.loads(request.data); print(data)

    #data = request.json
    required_columns = ["message_id", "entity_id", "category", "message_body"]
    
    # Check for missing columns
    missing_columns = [col for col in required_columns if col not in data.get("qry")]
    if missing_columns:
        print("missing")
        return jsonify({'error': f"Missing columns: {', '.join(missing_columns)}"}), 400
    print("function call")
    # Insert data into the entity table
    #success, message = insert_ignore(json_data['db_name'],json_data['System Config']['com_settings'], data.get("qry"))
    success, message = insert_ignore(json_data['db_name'],json_data[data['tab']][data['type']], data['qry'])
    
    if success:
        return jsonify({'message': message}), 201
    else:
        return jsonify({'error': message}), 400

# List
@app.route('/message/list_details', methods=['POST', 'GET'])
def message_list():
    f=open('config/new/get_DB_data.json');  json_data = json.load(f)
    print("db name: ",json_data)
    data = json.loads(request.data); print(data)
    
    try:
        myresult=get_data(json_data['db_name'],json_data['general']['message_table_name'], data['qry']['select_fields'],data['qry']['where_data']) 
        print(myresult)
        if(data['qry']['where_data']=={}):
            return jsonify([myresult])
        else:
            return jsonify([myresult])
     
    except Exception as e:
        print("Error:", e)
        return jsonify({"error": str(e)}), 500

# Update 
@app.route('/message/modifications', methods=['PUT'])
def message_update():
    f=open('config/new/get_DB_data.json');  json_data = json.load(f)
    print("db name: ",json_data['db_name'])
    data = request.json
    update_data = data.get("qry")
    where_data = {"message_id":data.get('message_id')}
    print(">>",update_data,where_data) 

    if not update_data or not where_data:
        return jsonify({"error": "Missing table_name, update_data or where_data"}), 400
    success = update_entry(json_data['db_name'],json_data['general']['message_table_name'], update_data,where_data,)
    if success:
        return jsonify({"message": "Entry updated successfully"}), 200
    else:
        return jsonify({"error": "Failed to update entry"}), 500

# Delete
@app.route('/message', methods=['DELETE'])
def message_delete():
    f=open('config/new/get_DB_data.json');  json_data = json.load(f)
    print("db name: ",json_data['db_name'])
    data = request.json
    where_data = data.get('where_data')

    success = delete_entry(json_data['general']['message_table_name'], where_data,json_data['db_name'])
    if success:
        return jsonify({"message": "Entry deleted successfully"}), 200
    else:
        return jsonify({"error": "Failed to delete entry"}), 500



######################################################  SUBSCRIBER  APIs  ####################################################################

#new
@app.route('/subscriber/new', methods=['POST'])
def subscriber_new():
    f=open('config/new/get_DB_data.json');  json_data = json.load(f)
    print("db name: ",json_data)
    data = request.json
    required_columns = ["subscriber_id", "name", "category", "phone_number", "email", "alert_url", "alert_preference", "status_poll_url"]
    
    # Check for missing columns
    missing_columns = [col for col in required_columns if col not in data.get("qry")]
    if missing_columns:
        return jsonify({'error': f"Missing columns: {', '.join(missing_columns)}"}), 400
    
    # Insert data into the entity table
    success, message = insert_ignore(json_data['db_name'],json_data['general']['subscriber_table_name'], data.get("qry"))
    
    if success:
        return jsonify({'message': message}), 201
    else:
        return jsonify({'error': message}), 400

# List
@app.route('/subscriber/list_details', methods=['POST', 'GET'])
def subscriber_list():
    f=open('config/new/get_DB_data.json');  json_data = json.load(f)
    print("db name: ",json_data)
    data = json.loads(request.data); print(data)
    
    try:
        myresult=get_data(json_data['db_name'],json_data['general']['subscriber_table_name'], data['qry']['select_fields'],data['qry']['where_data']) 
        print(myresult)
        if(data['qry']['where_data']=={}):
            return jsonify([myresult])
        else:
            return jsonify([myresult])
     
    except Exception as e:
        print("Error:", e)
        return jsonify({"error": str(e)}), 500

# Update 
@app.route('/subscriber/modifications', methods=['PUT'])
def subscriber_update():
    f=open('config/new/get_DB_data.json');  json_data = json.load(f)
    print("db name: ",json_data['db_name'])
    data = request.json
    update_data = data.get("qry")
    where_data = {"subscriber_id":data.get('subscriber_id')}
    print(">>",update_data,where_data) 

    if not update_data or not where_data:
        return jsonify({"error": "Missing table_name, update_data or where_data"}), 400
    success = update_entry(json_data['db_name'],json_data['general']['subscriber_table_name'], update_data,where_data,)
    if success:
        return jsonify({"message": "Entry updated successfully"}), 200
    else:
        return jsonify({"error": "Failed to update entry"}), 500

# Delete
@app.route('/subscriber', methods=['DELETE'])
def subscriber_delete():
    f=open('config/new/get_DB_data.json');  json_data = json.load(f)
    print("db name: ",json_data['db_name'])
    data = request.json
    where_data = data.get('where_data')

    success = delete_entry(json_data['general']['subscriber_table_name'], where_data,json_data['db_name'])
    if success:
        return jsonify({"message": "Entry deleted successfully"}), 200
    else:
        return jsonify({"error": "Failed to delete entry"}), 500

######################################################  LOG  APIs  ####################################################################

#new
@app.route('/log/new', methods=['POST'])
def log_new():
    f=open('config/new/get_DB_data.json');  json_data = json.load(f)
    print("db name: ",json_data)
    data = request.json
    required_columns = ["subscriber_id", "name", "category", "phone_number", "email", "alert_url", "alert_preference", "status_poll_url"]
    
    # Check for missing columns
    missing_columns = [col for col in required_columns if col not in data.get("qry")]
    if missing_columns:
        return jsonify({'error': f"Missing columns: {', '.join(missing_columns)}"}), 400
    
    # Insert data into the entity table
    success, message = insert_ignore(json_data['db_name'],json_data['general']['log_table_name'], data.get("qry") )
    
    if success:
        return jsonify({'message': message}), 201
    else:
        return jsonify({'error': message}), 400

# List
@app.route('/log/list_details', methods=['POST', 'GET'])
def log_list():
    f=open('config/new/get_DB_data.json');  json_data = json.load(f)
    print("db name: ",json_data)
    data = json.loads(request.data); print(data)
    
    try:
        myresult=get_data(json_data['db_name'],json_data['general']['log_table_name'], data['qry']['select_fields'],data['qry']['where_data']) 
        print(myresult)
        if(data['qry']['where_data']=={}):
            return jsonify([myresult])
        else:
            return jsonify([myresult])
     
    except Exception as e:
        print("Error:", e)
        return jsonify({"error": str(e)}), 500

# Update 
@app.route('/log/modifications', methods=['PUT'])
def log_update():
    f=open('config/new/get_DB_data.json');  json_data = json.load(f)
    print("db name: ",json_data['db_name'])
    data = request.json
    update_data = data.get("qry")
    where_data = {"log_id":data.get('log_id')}
    print(">>",update_data,where_data) 

    if not update_data or not where_data:
        return jsonify({"error": "Missing table_name, update_data or where_data"}), 400
    success = update_entry(json_data['db_name'],json_data['general']['log_table_name'], update_data,where_data,)
    if success:
        return jsonify({"message": "Entry updated successfully"}), 200
    else:
        return jsonify({"error": "Failed to update entry"}), 500

# Delete
@app.route('/log', methods=['DELETE'])
def log_delete():
    f=open('config/new/get_DB_data.json');  json_data = json.load(f)
    print("db name: ",json_data['db_name'])
    data = request.json
    where_data = data.get('where_data')

    success = delete_entry(json_data['general']['log_table_name'], where_data,json_data['db_name'])
    if success:
        return jsonify({"message": "Entry deleted successfully"}), 200
    else:
        return jsonify({"error": "Failed to delete entry"}), 500

######################################################  APPOINTMENT  APIs  ####################################################################

#new
@app.route('/appointment/new', methods=['POST'])
def appointment_new():
    f=open('config/new/get_DB_data.json');  json_data = json.load(f)
    print("db name: ",json_data)
    data = request.json
    required_columns = ["subscriber_id", "name", "category", "phone_number", "email", "alert_url", "alert_preference", "status_poll_url"]
    
    # Check for missing columns
    missing_columns = [col for col in required_columns if col not in data]
    if missing_columns:
        return jsonify({'error': f"Missing columns: {', '.join(missing_columns)}"}), 400
    
    # Insert data into the entity table
    success, message = insert_ignore(json_data['db_name'], json_data['general']['appointment_table_name'], data.get("qry") )
    
    if success:
        return jsonify({'message': message}), 201
    else:
        return jsonify({'error': message}), 400

# List
@app.route('/appointment/list_details', methods=['POST', 'GET'])
def appointment_list():
    f=open('config/new/get_DB_data.json');  json_data = json.load(f)
    print("db name: ",json_data)
    data = json.loads(request.data); print(data)
    
    try:
        myresult=get_data(json_data['db_name'],json_data['general']['appointment_table_name'], data['qry']['select_fields'],data['qry']['where_data']) 
        print(myresult)
        if(data['qry']['where_data']=={}):
            return jsonify([myresult])
        else:
            return jsonify([myresult])
     
    except Exception as e:
        print("Error:", e)
        return jsonify({"error": str(e)}), 500

# Update 
@app.route('/appointment/modifications', methods=['PUT'])
def appointment_update():
    f=open('config/new/get_DB_data.json');  json_data = json.load(f)
    print("db name: ",json_data['db_name'])
    data = request.json
    update_data = data.get("qry")
    where_data = {"appointment_id":data.get('appointment_id')}
    print(">>",update_data,where_data) 

    if not update_data or not where_data:
        return jsonify({"error": "Missing table_name, update_data or where_data"}), 400
    success = update_entry(json_data['db_name'],json_data['general']['appointment_table_name'], update_data,where_data,)
    if success:
        return jsonify({"message": "Entry updated successfully"}), 200
    else:
        return jsonify({"error": "Failed to update entry"}), 500

# Delete
@app.route('/appointment', methods=['DELETE'])
def appointment_delete():
    f=open('config/new/get_DB_data.json');  json_data = json.load(f)
    print("db name: ",json_data['db_name'])
    data = request.json
    where_data = data.get('where_data')

    success = delete_entry(json_data['general']['appointment_table_name'], where_data,json_data['db_name'])
    if success:
        return jsonify({"message": "Entry deleted successfully"}), 200
    else:
        return jsonify({"error": "Failed to delete entry"}), 500

######################################################  ENTITY_CONFIG  APIs  ####################################################################

#new
@app.route('/config/new', methods=['POST'])
def entityConfig_new():
    f=open('config/new/get_DB_data.json');  json_data = json.load(f)
    print("db name: ",json_data)
    data = request.json
    print(data.get("qry"))
    # Insert data into the entity table
    print(">>",json_data['db_name'],json_data[data['tab']][data['type']], data.get("qry") )
    success, message = insert_ignore(json_data['db_name'],json_data[data['tab']][data['type']], data.get("qry") )
    
    if success:
        return jsonify({'message': message}), 201
    else:
        return jsonify({'error': message}), 400

# List
@app.route('/config/list_details', methods=['POST', 'GET'])
def entityConfig_list():
    f=open('config/new/get_DB_data.json');  json_data = json.load(f)
    print("db name: ",json_data)
    data = json.loads(request.data); print(data)
    
    try:
        myresult=get_data(json_data['db_name'],json_data[data['tab']][data['type']], data['qry']['select_fields'],data['qry']['where_data']) 
        print(myresult)
        if(data['qry']['where_data']=={}):
            return jsonify(myresult,data['type'])
        else:
            return jsonify(myresult,data['type'])
     
    except Exception as e:
        print("Error:", e)
        return jsonify({"error": str(e)}), 500

# Update 
@app.route('/config/modifications', methods=['PUT'])
def entityConfig_update():
    f=open('config/new/get_DB_data.json');  json_data = json.load(f)
    print("db name: ",json_data['db_name'])
    data = request.json
    qry = data.get('qry', {})
    update_data = qry.get('update', {})
    where_data = qry.get('where_data', {})
    print(">>",update_data,where_data) 

    if not update_data or not where_data:
        return jsonify({"error": "Missing table_name, update_data or where_data"}), 400
    success = update_entry(json_data['db_name'],json_data[data['tab']][data['type']], update_data,where_data,)
    if success:
        return jsonify({"message": "Entry updated successfully"}), 200
    else:
        return jsonify({"error": "Failed to update entry"}), 500

# Delete
@app.route('/config', methods=['DELETE'])
def entityConfig_delete():
    f=open('config/new/get_DB_data.json');  json_data = json.load(f)
    print("db name: ",json_data['db_name'])
    data = json.loads(request.data)
    qry = data.get('qry', {})

    print("Query Received:", qry)
    print("Query Received:", type(qry['where_data']))

     # Ensure 'where_data' is always a dictionary
    where_data = qry.get('where_data', {})
    for key in where_data.keys():
        print(key)

    if isinstance(where_data, str):  
        try:
            where_data = json.loads(where_data)  # Convert string to dictionary
        except json.JSONDecodeError:
            return jsonify({'error': 'Invalid format for where_data'}), 400

    if not isinstance(where_data, dict):  
        return jsonify({'error': 'where_data must be a dictionary'}), 400

    print("Processed Where Data:", where_data)
    #success = delete_entry(json_data['db_name'],json_data['entity_config'][data['type']], {"entity_id":entity_id} )
    success = delete_entry(json_data['db_name'],json_data[data['tab']][data['type']], where_data)
    if success:
        return jsonify({"message": "Entry deleted successfully"}), 200
    else:
        return jsonify({"error": "Failed to delete entry"}), 500


if __name__ == '__main__':
   app.run(host='0.0.0.0', port=5000, debug=True)
   
from datetime import date, timedelta, datetime
import json

from django.http import HttpResponse, JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from pymongo import MongoClient
from uuid import uuid4

# Create your views here.
mongo_connect_string = "mongodb://gsp:rootpass@localhost:27017/"
client = MongoClient(mongo_connect_string)
db = client['exl']
template_collection = db['templates']
report_collection = db['reports']
users_collection = db['users']


@csrf_exempt
def user(request):
    if request.method == "GET":
        #View User
        return get_user(request)
    elif request.method  == "DELETE":
        #Delete User
        return delete_user(request)
    elif request.method  == "PUT":
        #Modify User
        return modify_user(request)
    elif request.method  == "POST":
        #Create User
        return create_user(request)

def create_user(request_in):
    user_json = json.loads(request_in.body.decode('utf-8'))
    user_name = user_json.get("user_name")
    company_name =  user_json.get("company_name")
    templates = user_json.get("templates")
    modified_on = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    guest_mode = user_json.get("guest_mode")
    #Generate Token
    user_token = uuid4()
    end_time = "NA"
    #if guest mode enabled today + stay_period days
    primary_key = company_name + "-" + user_name
    if guest_mode == "enabled":
        days_req = user_json.get("stay_period")
        current_date = date.today()
        newdate = current_date + timedelta(days=days_req)
        print(newdate)
        end_time=newdate.strftime("%d/%m/%Y %H:%M:%S")

    pay_load = {
        "user_id": primary_key,
        "user_name": user_name,
        "templates": templates,
        "token": user_token,
        "guest_mode": guest_mode,
        "updated_on": modified_on,
        "end_time": end_time
    }

    print(pay_load)
    try:
        result = users_collection.insert_one(pay_load)
        print("Object inserted")
    except Exception as e:
        print("LOl, Messedup")
        print(e)
        return HttpResponse("Template Upload failed")
    response =  {
            "user_id": pay_load["user_id"],
            "user_token": pay_load["token"],
            "guest_mode": pay_load["guest_mode"],
            "allowed_templates": pay_load["templates"],
            "end_time": pay_load["end_time"]
            }
    return JsonResponse(response, safe=False)

def modify_user(request_in):

    user_json = json.loads(request_in.body.decode('utf-8'))
    primary_key = user_json.get("user_id")
    user_name = user_json.get("user_name")
    templates = user_json.get("templates")
    modified_on = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    guest_mode = user_json.get("guest_mode")
    #Generate Token
    #user_token = uuid4()
    end_time = "NA"

    #if guest mode enabled today + stay_period days
    
    if guest_mode == "enabled":
        days_req = user_json.get("stay_period")
        current_date = date.today()
        newdate = current_date + timedelta(days=days_req)
        print(newdate)
        end_time=newdate.strftime("%d/%m/%Y %H:%M:%S")
    
    pay_load = {
        "user_id": primary_key,
        "user_name": user_name,
        "templates": templates,
        #"token": user_token,
        "guest_mode": guest_mode,
        "updated_on": modified_on,
        "end_time": end_time
    }

    print(pay_load)
    try:
        result = users_collection.update_one({"user_id" : primary_key}, { '$set' : {"user_name": user_name, "templates": templates, "guest_mode": guest_mode, "updated_on": modified_on, "end_time": end_time}})
        print("User Modified")
    except Exception as e:
        print("LOl, Messedup")
        print(e)
        return HttpResponse("User Modification Failed") 

    # response =  {
    #         "user_id": primary_key,
    #         "user_token": pay_load["token"],
    #         "guest_mode": pay_load["guest_mode"],
    #         "allowed_templates": pay_load["templates"],
    #         "end_time": pay_load["end_time"]
    #         }
    print(result)
    return get_user(request_in)

def get_user(request_in):
    user_json = json.loads(request_in.body.decode('utf-8'))
    primary_key = user_json.get("user_id")

    try:
        user_details = users_collection.find_one({"user_id": primary_key}, {"_id": 0})
    except Exception:
        return HttpResponse("Not Able to fetch user object")
    
    return JsonResponse(user_details, safe=False)

def delete_user(request_in):
    user_json = json.loads(request_in.body.decode('utf-8'))
    primary_key = user_json.get("user_id")

    try:
        user_details = users_collection.delete_one({"user_id": primary_key})
        print(f"Deleted user: {primary_key}")
    except Exception:
        return HttpResponse("Not Able to fetch template object")
    
    return HttpResponse(f"Deleted user: {primary_key}")

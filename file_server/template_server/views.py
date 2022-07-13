import json
import base64
import uuid
from urllib import response
from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from pymongo import MongoClient
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt

# Create your views here.
mongo_connect_string = "mongodb://gsp:rootpass@localhost:27017/"
client = MongoClient(mongo_connect_string)
db = client['exl']
template_collection = db['templates']
report_collection = db['reports']
users_collection = db['users']

@csrf_exempt
def template(request):
    user_status = check_user_validity(request)
    if user_status != "user":
        print(user_status)
        return HttpResponse("Unauthorized request")
    
    if request.method == "GET":
        return fetch_template(request)
    elif request.method == "PUT":
        return modify_template(request)
    elif request.method  == "POST":
        return create_template(request)
    elif request.method  == "DELETE":
        return delete_template(request)
    else:
        return HttpResponse("Bad Request \n Method Not Allowed")
    
def create_template(request_in):
    template_json = json.loads(request_in.body.decode('utf-8'))
    template_name = template_json.get("template_name")
    company_name = template_json.get("company_name")
    compression_algo = template_json.get("compression_algo")
    encrypt_key = template_json.get("encrypt_key")

    storage_points = template_json.get("storage_points")
    file_name_patterns = template_json.get("file_name_patterns")

    optimal_store_point = "Decide by internal Processing"
    primary_key = company_name + "-" + template_name
    pay_load = {
        "template_id": primary_key,
        "template_name": template_name,
        "company_name": company_name,
        "encrypt_key": encrypt_key,
        "compression_algo": compression_algo,
        "storage_points": storage_points,
        "optimal_store_point": optimal_store_point,
        "file_name_patterns": file_name_patterns
    }
    print(pay_load)
    try:
        result = template_collection.insert_one(pay_load)
        print("Object inserted")
    except Exception as e:
        print("LOl, Messedup")
        print(e)
        return HttpResponse("Template Upload failed")

    response = HttpResponse(result.inserted_id)

    return response


def fetch_template(request_in):
    print("Get request")
    template_json = json.loads(request_in.body.decode('utf-8'))
    template_name = template_json.get("template_name")
    company_name = template_json.get("company_name")
    try:
        template_details = template_collection.find_one({"template_name": template_name, "company_name": company_name}, {"_id": 0})
    except Exception:
        return HttpResponse("Not Able to fetch template object")
    
    print(type(template_details))
    print(template_details["template_name"])
    return JsonResponse(template_details, safe=False)

def modify_template(request_in):

    template_json = json.loads(request_in.body.decode('utf-8'))
    
    template_name = template_json.get("template_name")
    company_name = template_json.get("company_name")
    compression_algo = template_json.get("compression_algo")
    encrypt_key = template_json.get("encrypt_key")

    storage_points = template_json.get("storage_points")
    file_name_patterns = template_json.get("file_name_patterns")

    optimal_store_point = "Decide by internal Processing"
    template_id = company_name + "-" + template_name
    pay_load = {
        "template_id": template_id,
        "template_name": template_name,
        "company_name": company_name,
        "encrypt_key": encrypt_key,
        "compression_algo": compression_algo,
        "storage_points": storage_points,
        "optimal_store_point": optimal_store_point,
        "file_name_patterns": file_name_patterns
    }

    report_template_link_status = check_report_template_dependency(company_name, template_name)
    if report_template_link_status != "OK":
        return HttpResponse(report_template_link_status)
    
    try:
        result = template_collection.replace_one({'template_id': template_id}, pay_load)
        print("Object Modified")
    except Exception :
        print("LOl, Messedup")
        print(Exception)
        return HttpResponse("Template Modification failed")

    print(result)
    return HttpResponse(status=200, content="Object modified")

def delete_template(request_in):
    print("Get request")
    template_json = json.loads(request_in.body.decode('utf-8'))
    template_name = template_json.get("template_name")
    company_name = template_json.get("company_name")

    try:
        template_details = template_collection.delete_one({"template_name": template_name, "company_name": company_name})
    except Exception:
        return HttpResponse("Not Able to fetch template object")
    
    print(type(template_details))
    return HttpResponse("Object Deleted")

def check_report_template_dependency(company_name, template_name):
    template_id = company_name + "-" + template_name
    try:
        template_coupled = report_collection.find_one({"template_id": template_id }, {"_id": 0})
    except Exception as e:
        print(e)
        return "Not Able check template-report relationship"
    
    if template_coupled == None:
        #print(template_coupled, type(template_coupled))
        return "OK"
    else:
        #print(template_coupled, type(template_coupled), "NOt None")
        return "There's alredy a report using this template, unless versioning templates is implemented modification not allowed"

def check_user_validity(request_in):
    auth_header = request_in.META['HTTP_AUTHORIZATION']
    encoded_credentials = auth_header.split(' ')[1]  # Removes "Basic " to isolate credentials
    decoded_credentials = base64.b64decode(encoded_credentials).decode("utf-8").split(':')
    username = decoded_credentials[0]
    password = str(decoded_credentials[1])
    user_data = get_user_token(username)
    
    token_str = str(user_data["token"])
    print(token_str, password)
    if token_str != password:
        return "none"
    elif token_str == password and user_data["guest_mode"]=="enabled":
        print("Guest Request to Template Server")
        return "guest"
    else:
        return "user"

def get_user_token(user_id):
    
    primary_key = user_id

    try:
        user_details = users_collection.find_one({"user_id": primary_key}, {"token": 1, "guest_mode": 1})
    except Exception:
        return HttpResponse("Not Able to fetch template object")
    
    return user_details
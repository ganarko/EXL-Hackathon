from datetime import timedelta
from django.http import HttpResponse, JsonResponse
from pymongo import MongoClient
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from fpdf import FPDF
from minio import Minio
from minio.error import S3Error
import json

management_id = "exl"
mongo_connect_string = "mongodb://gsp:rootpass@localhost:27017/"
client = MongoClient(mongo_connect_string)
db = client['exl']
report_collection = db['report_saver_file']
template_collection = db['template_server_template']

#Object stores mimicking gcs and s3
client_aws = Minio(
        "localhost:9020",
        access_key="12345678",
        secret_key="password",
        secure=False,
)
client_gcp = Minio(
        "localhost:9010",
        access_key="12345678",
        secret_key="password",
        secure=False,
    )


@csrf_exempt
def report(request):
    report_json = json.loads(request.body.decode('utf-8'))
    company_name = report_json.get("company_name")
    report_name = report_json.get("report_name")

    if request.method == "GET":
        download_links = report_json.get("download_links")
        report = get_report_data(report_name, company_name, download_links)
        return JsonResponse(report, safe=False)
    elif request.method  == "DELETE":
        removed_report_status = delete_report(report_name,company_name)
        return HttpResponse(removed_report_status)
    elif request.method  == "PUT":
        return HttpResponse("Report Storage pattern modification is not allowed as of now")
    
    content = report_json.get("content")
    print(company_name,report_name) 


    #gather the Template data for specific Report name/Pattern
    template_data = find_templete_modify(report_name, company_name)

    if template_data is None:
        return HttpResponse("Unable Find Suited Template")

    #generate a pdf file with given content/txt
    generated_report_name = generate_temp_report(report_name, content)

    #Encrypt Report
    encrypted_report_name = encrypt_report(generated_report_name, template_data)

    #compress Report
    compressed_report_name = compress_report(encrypted_report_name, template_data)

    storage_bucket_object_ids = save_report_cloud(template_data, compressed_report_name, company_name)

    if storage_bucket_object_ids is None:
        return HttpResponse("Unable to Store report in Cloud")
    
    save_report_object(compressed_report_name, template_data, storage_bucket_object_ids)

    return JsonResponse(storage_bucket_object_ids, safe=False)

def get_object_download_link(report_details):
    object_download_links = []
    if report_details is None:
        return None

    storage_ponits = report_details['storage_object_ids']

    for a in storage_ponits:
        #Func to delete Object
        cloud_provider = a.split('-')[0]
        cloud_provider_client =  ""
        bucket_name = a.split('_')[0]
        object_id = a

        if cloud_provider == "aws":
            cloud_provider_client = client_aws
        elif cloud_provider == "gcp":
            cloud_provider_client = client_gcp
        else:
            print("Unable to Read Client, object not removed")
            return "Not Able to delete report Object"
        object_link = get_object(cloud_provider_client, bucket_name, object_id)
        object_download_links.append(object_link)

    objcet_details =  object_download_links
    return objcet_details

def get_report_data(filename,company_name, download_links):
    print("Getting Report Metadata")
    try:
        report_details = report_collection.find_one({"company_name": company_name ,"name": filename}, {"_id": 0, "company_name": 0 } )
    except Exception as e:
        print(e)
        return HttpResponse("Not able to fetch Report")
    
    print(type(report_details))
    
    if report_details is None:
        return None
    if download_links == "enabled":
        report_details["object_download_links"] = get_object_download_link(report_details)
    
    print(report_details["name"])
    return report_details

def delete_report(reportname,company_name):
    report_details = get_report_data(reportname, company_name, download_links="disabled")
    if report_details is None:
        return HttpResponse("No such Report Exists")
    storage_ponits = report_details['storage_object_ids']

    for a in storage_ponits:
        #Func to delete Object
        cloud_provider = a.split('-')[0]
        cloud_provider_client =  ""
        bucket_name = a.split('_')[0]
        object_id = a

        if cloud_provider == "aws":
            cloud_provider_client = client_aws
        elif cloud_provider == "gcp":
            cloud_provider_client = client_gcp
        else:
            print("Unable to Read Client, object not removed")
            return "Not Able to delete report Object"
        
        delete_object(cloud_provider_client, bucket_name, object_id)
        print(f"Report Document removed from: {a}")
    
    try:
        report_delete_status = report_collection.delete_one({"name": reportname, "company_name": company_name})
        print("Report footprint in mongoDb removed")
    except Exception as e:
        print(e)
        return "Not Able to delete report Object in MongoDB"
    #Deleted  Report
    return f"{reportname} is Deleted successfully"

def generate_temp_report(report_name, content):
    pdf = FPDF()
 
    # Add a page
    pdf.add_page()
    
    # set style and size of font
    # that you want in the pdf
    pdf.set_font("Arial", size = 15)
    
    # create a cell
    pdf.cell(200, 10, txt = content,
            ln = 1, align = 'C')
    
    # add another cell
    pdf.cell(200, 10, txt = "Sample Report Generated by Report Server",
            ln = 2, align = 'C')
    
    # save the pdf
    pdf.output(f"temp-reports/{report_name}") 
    #generate a pdf report
    return f"{report_name}"

def find_templete_modify(filename,company_name):
    print("Getting Template")
    try:
        template_details = template_collection.find_one({"company_name": company_name, "file_name_patterns": filename}, {"_id": 0, "file_name_patterns": 0} )
    except Exception as e:
        print("not able to Fetch the Template")
        print(e)
        return None
    
    print(type(template_details))
    if template_details is None:
        return None
    
    print(template_details["template_name"])
    return template_details

def encrypt_report(file_path, template_data):

    #return path of the encrypted and remove raw report
    print(template_data['encrypt_key'],"Encrypting")
    return file_path

def compress_report(file_path, template_data):

    print(template_data['compression_algo'],"Compressing")
    #return compressed report
    return file_path

def save_report_object(report_name, template_json, storage_object_ids):

    template_id = template_json["template_id"]
    company_name = template_json.get("company_name")

    storage_points = template_json["storage_points"]
    
    optimal_store_point = template_json["optimal_store_point"]
    primary_key = company_name + "-" + report_name
    pay_load = {
        "report_id": primary_key,
        "name": report_name,
        "template_id": template_id,
        "company_name": company_name,
        "storage_object_ids": storage_object_ids,
        "storage_points": storage_points,
        "optimal_store_point": optimal_store_point
    }
    print(pay_load)
    try:
        result = report_collection.insert_one(pay_load)
        print("Report metadata Object inserted")
    except Exception as e:
        print("LOl, Messedup")
        print(e)

def save_report_cloud(template_data, report_name, company):
    #return dict of all storage bucket end points
    storage_points = template_data['storage_points']
    object_ids = []
    for storage_point in storage_points:
       object_id = upload_file_cloud(storage_point, report_name, company)
       
       if object_id is None:
        #Schedule Reupload of the Object/Handle Exception
        print(f"For this {storage_point}, object upload Failed")
       else:
        object_ids.append(object_id)
    
    return object_ids

def upload_file_cloud(storage_id_string, reportname, company):
    storage_details = storage_id_string.split('-')
    cloud_service_provider = storage_details[0]
    provider_region = storage_details[1]
    storage_type = storage_details[2]

    file_address = f"temp-reports/{reportname}"
    bucket_name = cloud_service_provider + "-" + provider_region + "-" + storage_type + "-" + management_id

    saved_object_id = ""

    if(cloud_service_provider == "gcp"):
        saved_object_id = put_object(client_gcp,bucket_name, file_address, company, reportname)
    elif(cloud_service_provider == "aws"):
        saved_object_id = put_object(client_aws,bucket_name, file_address, company, reportname)
    else:
        print("Chosen Cloud provider Does not exist")
        return None
    return saved_object_id

def put_object(client, bucket, report_address, company, reportname):
    found = client.bucket_exists(bucket)
    object_id =  bucket + "_" + company + "_" + reportname
    if not found:
        print("Bucket Does not Exist, creating Bucket")
        client.make_bucket(bucket)
    else:
        print("Bucket already exists")
    try:
        result = client.fput_object(
            bucket, object_id, report_address,
            )
        
        print(result)
        return object_id
    except S3Error as e:
        print(e)
        return None

def get_object(client, bucket, object_id):
    # downloaded_file = "downloaded-"+ reportname
    # object_id =  company + "-" + reportname
    url = client.get_presigned_url(
        "GET",
        bucket,
        object_id,
        expires=timedelta(hours=24),
    )
    print(url)
    return url

def delete_object(client, bucket, object_id):
    client.remove_object(bucket, object_id)


# Check auth for uploading report | Not Implemented YET
def check_auth_api_key_upload():
    #No access for Guests only Token with report generator is valid
    auth_status =False
    return auth_status

# Check auth while retrieving reports
def auth_type_view_report():
    guest_access = "Verify relevant temporary token"
    ligit_user = "Find Relavant assigned token"

# When local or client side encryption is being used | Not Implemented YET
def decrypt_file_object(file_path, key):
    return 0

# When local compression is being used  | Not Implemented YET
def decompress_file_object(file_path, compression_algo):
    return 0
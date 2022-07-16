#For intermediary Computation
import json
import os
import binascii
import collections
import datetime
import hashlib
import six
import base64
from fpdf import FPDF
from datetime import timedelta

#For Mongo DB
from pymongo import MongoClient

#For MinIo  to Demonstrate multi cloud - Multi Region Multi Storage-Class Functionality
from minio import Minio
from minio.error import S3Error

#For AWS S3-Ops
import boto3
from botocore.client import Config

#For GCP GCS-Ops
from google.oauth2 import service_account
from six.moves.urllib.parse import quote
from google.cloud import storage

#For Django 
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt


#MongoDB Config
mongo_connect_string = "mongodb://gsp:rootpass@localhost:27017/"
client = MongoClient(mongo_connect_string)
db = client['exl']
template_collection = db['templates']
report_collection = db['reports']
users_collection = db['users']

#Cloud Buckets
GCS_BUCKET = "exl-file-storage"
GCS_CREDENTIALS_FILE = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
AWS_BUCKET = "aws-use2-standard-exl"
EXECUTE_TO_CLOUD = False

#Object stores mimicking gcs and s3
management_id = "exl"
client_azure = Minio(
        "localhost:9020",
        access_key="12345678",
        secret_key="password",
        secure=False,
)
client_oci = Minio(
        "localhost:9010",
        access_key="12345678",
        secret_key="password",
        secure=False,
    )


@csrf_exempt
def report(request):
    
    report_json = json.loads(request.body.decode('utf-8'))

    user_status = check_user_validity(request, report_json)
    
    if user_status != "user" and user_status != "none" and user_status != "guest":
        return HttpResponse(user_status)

    if user_status == "none":
        return HttpResponse("Unauthorized request | no user found")
    
    company_name = report_json.get("company_name")
    report_name = report_json.get("report_name")

    #Allowed guests and users
    if request.method == "GET" :
        download_links = report_json.get("download_links")
        return get_report_data(report_name, company_name, download_links, report_json)
    #Allowed users Only
    elif request.method  == "DELETE" and user_status=="user":
        return delete_report(report_name, company_name, report_json)
    #Allowed users Only
    elif request.method  == "PUT" and user_status=="user":
        return HttpResponse("Report Storage pattern modification is not allowed as of now")
    
    if user_status=="guest":
        return HttpResponse("Guest Users can only VIEW Reports | Only guest Access")
    
    #Allowed users Only create report from text content sample
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

def check_user_validity(request_in, report_json):

    try: 
        auth_header = request_in.META['HTTP_AUTHORIZATION']
    except Exception as e:
        print(e)
        return HttpResponse("Bad request | No Creds")
    
    encoded_credentials = auth_header.split(' ')[1]  # Removes "Basic " to isolate credentials
    decoded_credentials = base64.b64decode(encoded_credentials).decode("utf-8").split(':')
    username = decoded_credentials[0]
    password = decoded_credentials[1]
    get_user_token(username)
    
    
    if str(user_data["token"]) != password:
        return "none"
    elif str(user_data["token"]) == password and user_data["guest_mode"]=="enabled":

        #verify time for the guest
        end_time_limit = report_json.get("time_limit")
        end_time = user_data['end_time']
        current_check_time = datetime.datetime.now() + timedelta(hours=end_time_limit)
        current_check_time = current_check_time.strftime("%d/%m/%Y %H:%M:%S")
        if end_time < current_check_time:
            print(end_time_limit, current_check_time, "Access Request exceeds time Limit | increase guest Time Limit")
            return "Access Request exceeds time Limit | increase guest Time Limit"
        
        #verify template - report relationship for the guest
        company_name = report_json.get("company_name")
        report_name = report_json.get("report_name")
        try:
            global report_details
            report_details = report_collection.find_one({"company_name": company_name ,"name": report_name}, {"_id": 0, "company_name": 0 } )
        except Exception as e:
            print(e)
            return "Not able to fetch requested Report data"
        if report_details == None:
            return "Not able to fetch requested Report data"
            
        if report_details['template_id'] not in user_data['templates']:
            print("Guest user requesting Report | Forbidden ")
            return "Guest user requesting Report | Forbidden Request"

        return "guest"
    else:
        return "user"

def get_user_token(user_id):
    primary_key = user_id

    try:
        user_details = users_collection.find_one({"user_id": primary_key}, {"token": 1, "guest_mode": 1, "end_time":1, "templates":1})
    except Exception:
        return HttpResponse("Not Able to fetch template object")
    
    global user_data 
    user_data = user_details

def get_object_download_link(report_details, time_limit):
    
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

        if cloud_provider == "oci":
            cloud_provider_client = client_oci
            object_link = get_object(cloud_provider_client, bucket_name, object_id, time_limit)
        elif cloud_provider == "azure":
            cloud_provider_client = client_azure
            object_link = get_object(cloud_provider_client, bucket_name, object_id, time_limit)
        elif bucket_name == "gcs" and EXECUTE_TO_CLOUD:
          expiration = 60*60*time_limit
          object_link = generate_signed_url_gcp(GCS_CREDENTIALS_FILE, GCS_BUCKET, object_id, expiration)
        elif bucket_name == "s3" and EXECUTE_TO_CLOUD:
          expiration = 60*60*time_limit
          object_link = get_presigned_url_aws(AWS_BUCKET, object_id, expiration)
        else:
            print("Unable to Read Client, object url not fetched")
            return "Not Able to get report Object"
        
        object_download_links.append(object_link)

    objcet_details =  object_download_links
    return objcet_details

def get_report_data(filename, company_name, download_links, report_json):
    print("Getting Report Metadata")
    try:
        report_details = report_collection.find_one({"company_name": company_name ,"name": filename}, {"_id": 0, "company_name": 0 } )
    except Exception as e:
        print(e)
        return HttpResponse("Not able to fetch Report")
    
    print(type(report_details))
    
    if report_details is None:
        return HttpResponse("Not able to fetch Report")
    if download_links == "enabled":
        time_limit = report_json.get("time_limit")
        if report_details["template_id"] not in user_data['templates']:
            return HttpResponse("User Trying to View Report | Access denied")
        
        report_details["object_download_links"] = get_object_download_link(report_details, time_limit)
    
    print(report_details["name"])
    return JsonResponse(report_details, safe=False)

def delete_report(reportname,company_name, report_json_data):
    try:
        report_details = report_collection.find_one({"company_name": company_name ,"name": reportname}, {"_id": 0, "company_name": 0 } )
    except Exception as e:
        print(e)
        return HttpResponse("Not able to fetch Report")
    if report_details is None:
        return HttpResponse("No such Report Exists")
    storage_object_ids = report_details['storage_object_ids']
    delete_report_status = f"{reportname} is Deleted successfully in: "
    for a in storage_object_ids:
        #Func to delete Object
        cloud_provider = a.split('-')[0]
        cloud_provider_client =  ""
        bucket_name = a.split('_')[0]
        object_id = a

        if cloud_provider == "oci":
            cloud_provider_client = client_oci
            delete_object(cloud_provider_client, bucket_name, object_id)
            delete_report_status = delete_report_status + bucket_name + ", "
        elif cloud_provider == "azure":
            cloud_provider_client = client_azure
            delete_object(cloud_provider_client, bucket_name, object_id)
            delete_report_status = delete_report_status + bucket_name + ", "
        elif bucket_name == "gcs" and EXECUTE_TO_CLOUD:
            delete_blob_gcp(GCS_BUCKET, object_id)
            delete_report_status = delete_report_status + bucket_name + ", "
        elif bucket_name == "s3" and EXECUTE_TO_CLOUD:
            delete_object_aws(AWS_BUCKET, object_id)
            delete_report_status = delete_report_status + bucket_name + ", "
        else:
            print("Unable to Read Client, object not removed")
            return "Not Able to delete report Object"
        
        
        print(f"Report Document removed from: {bucket_name}")
    
    try:
        report_object_delete_status = report_collection.delete_one({"name": reportname, "company_name": company_name})
        print("Report footprint in mongoDb removed")
    except Exception as e:
        print(e)
        return "Not Able to delete report Object in MongoDB"
    #Deleted  Report
    return HttpResponse(f"{delete_report_status}")

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
        print(f"For {storage_point}, object upload Failed")
       else:
        object_ids.append(object_id)
    
    return object_ids

def upload_file_cloud(storage_id_string, reportname, company):
    

    if storage_id_string != "gcs" and storage_id_string != "s3":
        storage_details = storage_id_string.split('-')
        cloud_service_provider = storage_details[0]
        provider_region = storage_details[1]
        storage_type = storage_details[2]
        bucket_name = cloud_service_provider + "-" + provider_region + "-" + storage_type + "-" + management_id

    else:
        cloud_service_provider = storage_id_string

    file_address = f"temp-reports/{reportname}"
    
    saved_object_id = ""

    if(cloud_service_provider == "oci"):
        saved_object_id = put_object(client_oci, bucket_name, file_address, company, reportname)
    elif(cloud_service_provider == "azure"):
        saved_object_id = put_object(client_azure,bucket_name, file_address, company, reportname)
    elif(cloud_service_provider == "gcs" and EXECUTE_TO_CLOUD):
        object_id =  cloud_service_provider + "_" + company + "_" + reportname
        saved_object_id =  upload_blob_gcp(GCS_BUCKET,file_address,object_id )
    elif(cloud_service_provider == "s3" and EXECUTE_TO_CLOUD):
        object_id =  cloud_service_provider + "_" + company + "_" + reportname
        saved_object_id = store_object_aws(AWS_BUCKET, file_address, object_id)
    else:
        print("Chosen Cloud provider Does not exist")
        return None
    return saved_object_id

def put_object(client, bucket, report_address, company, reportname):
    
    object_id =  bucket + "_" + company + "_" + reportname
    
    try:
        found = client.bucket_exists(bucket)
        if not found:
            print("Bucket Does not Exist, creating Bucket")
            client.make_bucket(bucket)
        else:
            print("Bucket already exists")
        
        result = client.fput_object(
            bucket, object_id, report_address,
            )
        
        print(result)
        return object_id
    except Exception as e:
        print(e)
        return None

def get_object(client, bucket, object_id, time_limit):
    # downloaded_file = "downloaded-"+ reportname
    # object_id =  company + "-" + reportname
    url = client.get_presigned_url(
        "GET",
        bucket,
        object_id,
        expires=timedelta(hours=time_limit),
    )
    print(url)
    return url

def delete_object(client, bucket, object_id):
    client.remove_object(bucket, object_id)

# When local or client side encryption is being used | Not Implemented YET
def decrypt_file_object(file_path, key):
    return 0

# When local compression is being used  | Not Implemented YET
def decompress_file_object(file_path, compression_algo):
    return 0


# <---------------------- GCP GCS Storage Functions ---------------------->

def upload_blob_gcp(bucket_name, source_file_name, destination_blob_name):
    """Uploads a file to the bucket."""
    # The ID of your GCS bucket
    # bucket_name = "your-bucket-name"
    # The path to your file to upload
    # source_file_name = "local/path/to/file"
    # The ID of your GCS object
    # destination_blob_name = "storage-object-name"

    storage_client = storage.Client()
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(destination_blob_name)

    blob.upload_from_filename(source_file_name)

    print(
        f"File {source_file_name} uploaded to {destination_blob_name}."
    )
    return destination_blob_name

def download_blob_gcp(bucket_name, source_blob_name, destination_file_name):
    """Downloads a blob from the bucket."""
    # The ID of your GCS bucket
    # bucket_name = "your-bucket-name"

    # The ID of your GCS object
    # source_blob_name = "storage-object-name"

    # The path to which the file should be downloaded
    # destination_file_name = "local/path/to/file"

    storage_client = storage.Client()

    bucket = storage_client.bucket(bucket_name)

    # Construct a client side representation of a blob.
    # Note `Bucket.blob` differs from `Bucket.get_blob` as it doesn't retrieve
    # any content from Google Cloud Storage. As we don't need additional data,
    # using `Bucket.blob` is preferred here.
    blob = bucket.blob(source_blob_name)
    blob.download_to_filename(destination_file_name)

    print(
        "Downloaded storage object {} from bucket {} to local file {}.".format(
            source_blob_name, bucket_name, destination_file_name
        )
    )

def delete_blob_gcp(bucket_name, source_blob_name):
    """Deletes a blob from the bucket."""
    # bucket_name = "your-bucket-name"
    # blob_name = "your-object-name"

    storage_client = storage.Client()

    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(source_blob_name)
    blob.delete()

    print(f"Blob {source_blob_name} deleted.")

def generate_signed_url_gcp(service_account_file, bucket_name, object_name,
                        expiration, subresource=None, http_method='GET',
                        query_parameters=None, headers=None):

    if expiration > 604800:
        print('Expiration Time can\'t be longer than 604800 seconds (7 days).')
        return None

    escaped_object_name = quote(six.ensure_binary(object_name), safe=b'/~')
    canonical_uri = '/{}'.format(escaped_object_name)

    datetime_now = datetime.datetime.now(tz=datetime.timezone.utc)
    request_timestamp = datetime_now.strftime('%Y%m%dT%H%M%SZ')
    datestamp = datetime_now.strftime('%Y%m%d')

    google_credentials = service_account.Credentials.from_service_account_file(
        service_account_file)
    client_email = google_credentials.service_account_email
    credential_scope = '{}/auto/storage/goog4_request'.format(datestamp)
    credential = '{}/{}'.format(client_email, credential_scope)

    if headers is None:
        headers = dict()
    host = '{}.storage.googleapis.com'.format(bucket_name)
    headers['host'] = host

    canonical_headers = ''
    ordered_headers = collections.OrderedDict(sorted(headers.items()))
    for k, v in ordered_headers.items():
        lower_k = str(k).lower()
        strip_v = str(v).lower()
        canonical_headers += '{}:{}\n'.format(lower_k, strip_v)

    signed_headers = ''
    for k, _ in ordered_headers.items():
        lower_k = str(k).lower()
        signed_headers += '{};'.format(lower_k)
    signed_headers = signed_headers[:-1]  # remove trailing ';'

    if query_parameters is None:
        query_parameters = dict()
    query_parameters['X-Goog-Algorithm'] = 'GOOG4-RSA-SHA256'
    query_parameters['X-Goog-Credential'] = credential
    query_parameters['X-Goog-Date'] = request_timestamp
    query_parameters['X-Goog-Expires'] = expiration
    query_parameters['X-Goog-SignedHeaders'] = signed_headers
    if subresource:
        query_parameters[subresource] = ''

    canonical_query_string = ''
    ordered_query_parameters = collections.OrderedDict(
        sorted(query_parameters.items()))
    for k, v in ordered_query_parameters.items():
        encoded_k = quote(str(k), safe='')
        encoded_v = quote(str(v), safe='')
        canonical_query_string += '{}={}&'.format(encoded_k, encoded_v)
    canonical_query_string = canonical_query_string[:-1]  # remove trailing '&'

    canonical_request = '\n'.join([http_method,
                                   canonical_uri,
                                   canonical_query_string,
                                   canonical_headers,
                                   signed_headers,
                                   'UNSIGNED-PAYLOAD'])

    canonical_request_hash = hashlib.sha256(
        canonical_request.encode()).hexdigest()

    string_to_sign = '\n'.join(['GOOG4-RSA-SHA256',
                                request_timestamp,
                                credential_scope,
                                canonical_request_hash])

    # signer.sign() signs using RSA-SHA256 with PKCS1v15 padding
    signature = binascii.hexlify(
        google_credentials.signer.sign(string_to_sign)
    ).decode()

    scheme_and_host = '{}://{}'.format('https', host)
    signed_url = '{}{}?{}&x-goog-signature={}'.format(
        scheme_and_host, canonical_uri, canonical_query_string, signature)

    print(signed_url)
    return signed_url

# <---------------------- AWS S3 Storage Functions ---------------------->
def store_object_aws(bucket, report_address, object_id):
    s3 = boto3.client("s3")
    # Dynamically create buckets using createBucket call in boto3 client
    # found = s3.Bucket('Hello') in s3.buckets.all()
    s3.upload_file(
        Filename=report_address,
        Bucket=bucket,
        Key=object_id,
    )
    return object_id

def view_object_aws(bucket, object_id):
    s3 = boto3.client("s3")
    s3.download_file(
        Bucket=bucket, Key=object_id, Filename=f"downloded-{object_id}",
    )
    return "Done"

def get_presigned_url_aws(bucket_name, object_name, expiration):
    """Generate a presigned URL to share an S3 object

    :param bucket_name: string
    :param object_name: string
    :param expiration: Time in seconds for the presigned URL to remain valid
    :return: Presigned URL as string. If error, returns None.
    """

    # Generate a presigned URL for the S3 object
    s3_client = boto3.client('s3',config=Config(signature_version='s3v4', region_name='us-east-2'))
    try:
        response_url = s3_client.generate_presigned_url('get_object',
                                                    Params={'Bucket': bucket_name,
                                                            'Key': object_name},
                                                    ExpiresIn=expiration)
    except Exception as e:
        print(e)
        return
    
    print(response_url)
    return response_url

def delete_object_aws(bucket_name, file_name ):
    s3_client = boto3.client("s3")
    response = s3_client.delete_object(Bucket=bucket_name, Key=file_name)
    print(response)

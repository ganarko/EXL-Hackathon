import json
import binascii
import collections
import datetime
import hashlib
import six
import base64

from datetime import timedelta
from django.http import HttpResponse, JsonResponse
from pymongo import MongoClient
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from fpdf import FPDF
from minio import Minio
from minio.error import S3Error
from google.oauth2 import service_account
from six.moves.urllib.parse import quote

management_id = "exl"
mongo_connect_string = "mongodb://gsp:rootpass@localhost:27017/"
client = MongoClient(mongo_connect_string)
db = client['exl']
template_collection = db['templates']
report_collection = db['reports']
users_collection = db['users']

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
    
    user_status = check_user_validity(request)
    
    if user_status == "none":
        return HttpResponse("Unauthorized request | no user found")
    
    report_json = json.loads(request.body.decode('utf-8'))
    company_name = report_json.get("company_name")
    report_name = report_json.get("report_name")

    if request.method == "GET" :
        download_links = report_json.get("download_links")
        report = get_report_data(report_name, company_name, download_links)
        return JsonResponse(report, safe=False)
    elif request.method  == "DELETE" and user_status!="guest":
        removed_report_status = delete_report(report_name,company_name)
        return HttpResponse(removed_report_status)
    elif request.method  == "PUT" and user_status!="guest":
        return HttpResponse("Report Storage pattern modification is not allowed as of now")
    
    if user_status=="guest":
        return HttpResponse("Guest can VIEW Reports | Only guest Access")
    
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

def check_user_validity(request_in):
    try: 
        auth_header = request_in.META['HTTP_AUTHORIZATION']
    except Exception as e:
        print(e)
        return HttpResponse("Bad request | No Creds")
    
    encoded_credentials = auth_header.split(' ')[1]  # Removes "Basic " to isolate credentials
    decoded_credentials = base64.b64decode(encoded_credentials).decode("utf-8").split(':')
    username = decoded_credentials[0]
    password = decoded_credentials[1]
    user_data = get_user_token(username)
    
    if str(user_data["token"]) != password:
        return "none"
    elif str(user_data["token"]) == password and user_data["guest_mode"]=="enabled":
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


# <---------------------- GCP GCS Storage Functions ---------------------->

def upload_blob(bucket_name, source_file_name, destination_blob_name):
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
def download_blob(bucket_name, source_blob_name, destination_file_name):
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
def delete_blob(bucket_name, source_blob_name):
    """Deletes a blob from the bucket."""
    # bucket_name = "your-bucket-name"
    # blob_name = "your-object-name"

    storage_client = storage.Client()

    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(source_blob_name)
    blob.delete()

    print(f"Blob {source_blob_name} deleted.")
def generate_signed_url(service_account_file, bucket_name, object_name,
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

# EXL-Hackathon
EXL Hackathon Files
Use this branch to test prototype in docker environment

Make sure you have docker version as mentioned in versions.txt
Clone EXL files from this Branch

$git clone -b containarized https://github.com/ganarko/EXL-Hackathon.git EXL



Now, Execute the following commands:

$docker network create --subnet=172.20.0.0/24 file_server_net

--------------------------------- Setting Up mongo database ---------------------------------

$cd /path_to_EXL/EXL/dockersetups-prod/mongo-db

$docker compose up -d

$docker ps

If containers were created successfully,
You should see mongoDB and mongo-admin containers running
You can access mongoDB console in localhost:8081 | username:user, password: pass

--------------------------------- Setting Up Object Storage ---------------------------------

$cd /path_to_EXL/EXL/dockersetups-prod/minio

$docker compose up -d

$docker ps



If containers were created successfully,
You should see minio-azure and minio-oci containers running
You can access minio-azure,minio-oci consoles in localhost:9011 and localhost:9011 | username:12345678, password: password
#These two containers will help us to emulate behaviour of storage buckets in local environment, 
#Please refer Demo video to see reports being pushed to gcs and s3

--------------------------------- Starting App as Container ---------------------------------

Open New terminal

$cd /path_to_EXL/EXL/file_server

$docker build --no-cache --tag file_server:v1 .

$docker run --network file_server_net --name file_server -p 8000:8000 file_server:v1

$docker ps

If App container was created successfully,
You should see file_server running at this point
You shoud see file_server consoles in localhost:9011 and localhost:9011 | username:12345678, password: password


--------------------------------- API Testing via Postman ---------------------------------

Once this setup is done, import postman collection to postman

1) Generate users/guests first

2) payloads for all APIs were already provided along with examples

3) When sending the request just add the new password you generated in step-1, for respective user,guest


--------------------------------- Clean Up---------------------------------

Stop and Remove file_server container

$docker rm -f file_server

Stop and Remove mongoDB ---------------------------------

$cd /path_to_EXL/EXL/dockersetups-prod/mongo-db

$docker compose down

Stop and Remove MINIO containers ---------------------------------

$cd /path_to_EXL/EXL/dockersetups-prod/minio

$docker compose down


Remove App Image ---------------------------------

$docker rmi -f file-server:v1

Remove network ---------------------------------

$docker network rm file_server_net

#Clean Files 

rm -rf /path_to_EXL/EXL/

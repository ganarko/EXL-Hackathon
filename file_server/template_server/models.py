from django.db import models
from django.contrib.postgres.fields import ArrayField
from uuid import uuid4
# Create your models here.
class template(models.Model):
    template_name = models.CharField(max_length=255,default="xxx-template")
    company_name = models.CharField(max_length=255, default="xxx")

    created_time = models.DateTimeField(auto_now=True)
    updated_time = models.DateTimeField(auto_now=True)

    encrypt_key = models.CharField(max_length=600,null=True)
    compressing_algo = models.CharField(max_length=255,null=True)

    storage_points = ArrayField(models.CharField(max_length=255),null=True)
    #Format: Cloud_Provider-Region-Storage_type-Client_name/id
    
    optimal_store_point = models.CharField(max_length=255,null=True)

    file_name_patterns = ArrayField(models.CharField(max_length=150),null=True)

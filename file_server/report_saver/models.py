from django.db import models
from django.contrib.postgres.fields import ArrayField
# Create your models here.

class File(models.Model):
    name = models.CharField(max_length=255,null=True)
    template_id = models.CharField(max_length=255,null=True)

    encrypt_key = models.CharField(max_length=255, null=True)
    compression_algo =  models.CharField(max_length=255, null=True)
    
    storage_object_ids = ArrayField(models.CharField(max_length=255, null=True), null=True)
    storage_points = ArrayField(models.CharField(max_length=255, null=True), null=True)

    optimal_store_point = models.CharField(max_length=255, null=True)
from django.contrib.auth.models import AbstractUser
from django.db import models

class EncryptUser(AbstractUser):
    phone = models.CharField(max_length=10, blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    key = models.CharField(max_length=16, blank=True, null=True)

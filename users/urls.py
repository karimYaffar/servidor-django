from django.urls import path
from .views import encrypt_fields, generate_3des_key, get_public_key

urlpatterns = [
    path('encrypt/', encrypt_fields, name='encrypt_fields'),
    path('generate-key/', generate_3des_key, name='generate_3des_key'),
    path('generate-public-key/',get_public_key, name='get_public_key')
]
from rest_framework import serializers

from .models import EncryptUser

class UserSerializers(serializers.ModelSerializer):
    class Meta:
        model = EncryptUser
        fields = ['username', 'password', 'email', 'phone', 'address', 'key']
        
    def create(self, validate_data):
        user = EncryptUser.objects.create_user(
            username= validate_data['username'],
            password= validate_data['password'],
            email   = validate_data['email'],
            phone   = validate_data['phone'],
            address = validate_data['address'],
            key     = validate_data['key']
        )
        return user
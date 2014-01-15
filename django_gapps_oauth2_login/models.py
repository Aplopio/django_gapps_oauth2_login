from django.db import models
from django.contrib.auth.models import User
from oauth2client.django_orm import FlowField
from oauth2client.django_orm import CredentialsField


class CredentialsModel(models.Model):
  id = models.ForeignKey(User, primary_key=True, related_name="user_credential")
  credential = CredentialsField()

class UserOauth2(models.Model):
    user = models.ForeignKey(User, related_name="oauth2_user")
    claimed_id = models.TextField(max_length=2047)
    display_id = models.TextField(max_length=2047)

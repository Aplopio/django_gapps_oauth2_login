from django.conf.urls import url
from django_gapps_oauth2_login.views import login_begin, auth_required

urlpatterns =[
    url(r'^login/$', login_begin),
    url(r'^oauth2callback/', auth_required),
]

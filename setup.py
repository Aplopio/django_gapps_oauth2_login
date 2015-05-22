from distutils.core import setup

long_description="""
django_gapps_oauth2_login
=========================

git clone https://github.com/Aplopio/django_gapps_oauth2_login.git

Download client secrets in json provided by google cloud console credentials & rename to client_secrets.json in this directory.

Add 'django_gapps_oauth2_login' to INSTALLED_APPS in settings.py

Update urls.py by adding following entry:

(r'^oauth2/', include('django_gapps_oauth2_login.urls'))

run python manage.py syncdb

Write custom receivers for user_created_via_oauth2 & redirect_user_loggedin_via_oauth2 signals

Run testcases, python manage.py test django_gapps_oauth2_login
"""

setup(name='django_gapps_oauth2_login',
      version='0.9.7.9',
      description='Django Google Apps Oauth2 Login',
      long_description = long_description,
      author='Vivek Chand',
      author_email='vivek@aplopio.com',
      url='https://github.com/Aplopio/django_gapps_oauth2_login',
      classifiers = [
          "Programming Language :: Python",
          "Topic :: Software Development :: Libraries :: Python Modules",
          "License :: OSI Approved :: MIT License",
          "Operating System :: OS Independent",
          "Development Status :: 5 - Production/Stable",
          "Intended Audience :: Developers",
          "Programming Language :: Python :: 2.6",
          "Programming Language :: Python :: 2.7",
      ],
      keywords = ["django ", "oauth2", "login"],
      packages = ['django_gapps_oauth2_login'],
      install_requires = ['google-api-python-client==1.2', 'mock==1.0.1', 'BeautifulSoup==3.2.1'],
      )

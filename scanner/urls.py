"""scanner URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from logs.views import front_view, unique_ip_list, unique_ip_country_list, attack_list, model_form_upload

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', model_form_upload, name='frontpage'),
    path('unique-ip-list/', unique_ip_list, name='uniqueIPList'),
    path('unique-ip-country-list/', unique_ip_country_list, name='uniqueIPCountryList'),
    path('attack-list/', attack_list, name='attackList'),
]

"""file_server URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.0/topics/http/urls/
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
from template_server import views as temp_srv_views
from report_saver import views as report_saver_views
from user_manager import views as user_manager_views
urlpatterns = [
    path('admin/', admin.site.urls),
    path('temp_server/template/', temp_srv_views.template),
    path('report_server/report/', report_saver_views.report),
    path('user_manager/user/', user_manager_views.user),
]

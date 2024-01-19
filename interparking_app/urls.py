from django.urls import path,re_path
from interparking_app import views
from django.conf.urls import include

app_name = 'interparking_app'

urlpatterns = [
        path('',views.user_login,name='user_login'),
        path('user_login',views.user_login,name='user_login'),
        path('quotadashboard',views.quota_dashboard,name='quota_dashboard'),
        path('logout',views.user_logout,name='logout')
]

from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('health', views.health, name='health'),
    path('health/db', views.db_health, name='db_health'),
]

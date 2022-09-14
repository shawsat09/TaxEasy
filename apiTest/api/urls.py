from django.conf.urls import url
from .views import UserCreations, UserLogin, UserUpdate,UserDetails
urlpatterns = [
    url('create/', UserCreations.as_view()),
    url('login/', UserLogin.as_view()),
    url('update/', UserUpdate.as_view()),
    url('view/', UserDetails.as_view()),
]
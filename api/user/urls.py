from rest_framework import routers
from django.urls import path, include

from . import views

router = routers.DefaultRouter()
router.register(r'', views.UserViewSet)

urlpatterns = [
    path('login/', views.signin, name="sigin"),
    path('logout/<int:id>/', views.signout, name="signout"),
    path('authenticate/<int:id>/<str:token>', views.authenticate_user, name="user.authenticate"),
    path('', include(router.urls))
]
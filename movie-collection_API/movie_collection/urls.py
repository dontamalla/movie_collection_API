from django.contrib import admin
from django.urls import path, include
from rest_framework_simplejwt import views as jwt_views
import movie.views
from movie.views import request_count, reset_request_count

from rest_framework import routers

router_v1 = routers.DefaultRouter()
router_v1.register(r"movies", movie.views.MovieViewSet)
router_v1.register(r"collections", movie.views.CollectionViewSet)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('register', movie.views.authenticate_user, name='register'),
    path("api/v1/", include(router_v1.urls), name="api-root"),
    path('api/token/', jwt_views.TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', jwt_views.TokenRefreshView.as_view(), name='token_refresh'),
    path('request-count/', request_count, name='request_count'),
    path('request-count/reset/', reset_request_count, name='reset_request_count'),
]


import jwt
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import generics, status
from movie.serializers import MovieSerializer, CollectionSerializer
from rest_framework.decorators import api_view, permission_classes
from django.contrib.auth.models import User
from rest_framework_jwt.settings import api_settings

from django.conf import settings
from movie.models import Movie, Collection
from rest_framework import status
from rest_framework import viewsets

from django.http import JsonResponse



counter = 0

class RequestCounterMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
    def __call__(self, request):
        global counter
        counter += 1
        response = self.get_response(request)
        return response

def reset_request_count(request):
    global counter
    counter = 0
    return JsonResponse({"message": "request count reset successfully"})

class MovieViewSet(viewsets.ModelViewSet):
    lookup_field = "uuid"
    queryset = Movie.objects.all()
    permission_classes = [IsAuthenticated]
    serializer_class = MovieSerializer


class CollectionViewSet(viewsets.ModelViewSet):
    lookup_field = "uuid"
    queryset = Collection.objects.all()
    permission_classes = [IsAuthenticated]
    serializer_class = CollectionSerializer

    def list(self, request):
        serializer = self.get_serializer(self.queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)




class HelloView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        content = {'message': 'Hello, World!'}
        return Response(content)


@api_view(['POST'])
@permission_classes([AllowAny, ])
def authenticate_user(request):
    jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
    jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
    data = request.data
    # user = User.objects.create(username=data['username'])
    user = request.data.get("username")
    inppasword = request.data.get("password")
    # user = User.objects.create(username=data['username'])
    user = User.objects.create(user)
    # user.set_password(data['password'])
    # user.set_password(data["inppasword"])
    if user:
        try:
            payload = jwt_payload_handler(user)
            token = jwt.encode(payload, settings.SECRET_KEY)
            return Response({'access_token': token }, status=status.HTTP_200_OK)
        except Exception as e:
            raise e
    else:
        res = {
            'error': 'can not authenticate with the given credentials or the account has been deactivated'}
        return Response(res, status=status.HTTP_403_FORBIDDEN)



def request_count(request):
    return JsonResponse({"requests": counter})

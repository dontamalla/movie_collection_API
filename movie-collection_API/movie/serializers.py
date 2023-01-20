from rest_framework import serializers
from movie.models import Movie, Collection


class MovieSerializer(serializers.ModelSerializer):
    class Meta:
        model = Movie
        fields = [
            "title",
            "description",
            "genres",
            "uuid",
        ]

class MovieUUIDSerializer(serializers.ModelSerializer):
    class Meta:
        model = Movie
        fields = [
            "uuid",
        ]


class CollectionSerializer(serializers.ModelSerializer):
    movies = MovieUUIDSerializer(many=True, read_only=True)

    class Meta:
        model = Collection
        fields = [
            "uuid",
            "title",
            "description",
            "movies",
        ]
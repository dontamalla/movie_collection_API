from django.db import models
from uuid import uuid4


class Movie(models.Model):
    title = models.CharField(max_length=100, null=False)
    description = models.TextField()
    genres = models.CharField(max_length=250)
    uuid = models.UUIDField(default=uuid4, editable=False, primary_key=True)

class Collection(models.Model):
    title = models.CharField(max_length=100, null=False)
    description = models.TextField()
    uuid = models.UUIDField(default=uuid4, editable=False, primary_key=True)
    movies = models.ManyToManyField(
        Movie,
        related_name="collections",
        through="MovieCollection",
        through_fields=("collection", "movie"),
    )

class MovieCollection(models.Model):
    collection = models.ForeignKey(Collection, on_delete=models.CASCADE)
    movie = models.ForeignKey(Movie, on_delete=models.CASCADE)




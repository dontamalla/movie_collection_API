
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('movie', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='movie',
            name='collection',
        ),
        migrations.CreateModel(
            name='MovieCollection',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('collection', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='movie.collection')),
                ('movie', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='movie.movie')),
            ],
        ),
        migrations.AddField(
            model_name='collection',
            name='movies',
            field=models.ManyToManyField(related_name='collections', through='movie.MovieCollection', to='movie.Movie'),
        ),
    ]

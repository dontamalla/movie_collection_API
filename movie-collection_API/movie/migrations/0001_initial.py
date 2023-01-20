
from django.db import migrations, models
import django.db.models.deletion
import uuid

class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Collection',
            fields=[
                ('title', models.CharField(max_length=100)),
                ('description', models.TextField()),
                ('uuid', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
            ],
        ),
        migrations.CreateModel(
            name='Movie',
            fields=[
                ('title', models.CharField(max_length=100)),
                ('description', models.TextField()),
                ('genres', models.CharField(max_length=250)),
                ('uuid', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('collection', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='movie.collection')),
            ],
        ),
    ]

# Generated by Django 5.1.2 on 2024-11-13 20:43

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0008_clientcertificate'),
    ]

    operations = [
        migrations.RenameModel(
            old_name='Post',
            new_name='TrendingPost',
        ),
    ]

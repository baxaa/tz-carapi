# Generated by Django 5.0.3 on 2024-03-12 15:59

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('library', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='customer',
            name='borrowed_books',
        ),
    ]

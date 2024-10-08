# Generated by Django 5.1 on 2024-08-10 08:42

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='FuelType',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='TransmissionType',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='Car',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('brand', models.CharField(max_length=255)),
                ('model', models.CharField(max_length=255)),
                ('year', models.IntegerField()),
                ('mileage', models.IntegerField()),
                ('price', models.FloatField()),
                ('fuel_type', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='cars.fueltype')),
                ('transmission', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='cars.transmissiontype')),
            ],
            options={
                'verbose_name': 'Машина',
                'db_table': 'car',
            },
        ),
    ]

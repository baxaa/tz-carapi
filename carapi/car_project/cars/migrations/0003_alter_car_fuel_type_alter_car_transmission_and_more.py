# Generated by Django 5.1 on 2024-08-10 08:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('cars', '0002_alter_fueltype_options_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='car',
            name='fuel_type',
            field=models.CharField(max_length=255),
        ),
        migrations.AlterField(
            model_name='car',
            name='transmission',
            field=models.CharField(max_length=255),
        ),
        migrations.DeleteModel(
            name='FuelType',
        ),
        migrations.DeleteModel(
            name='TransmissionType',
        ),
    ]

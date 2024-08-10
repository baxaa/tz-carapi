from django.db import models


class Car(models.Model):
    brand = models.CharField(max_length=255, null=False, blank=False)
    model = models.CharField(max_length=255, null=False, blank=False)
    year = models.IntegerField(null=False, blank=False)
    fuel_type = models.CharField(max_length=255, null=False, blank=False)
    transmission = models.CharField(max_length=255, null=False, blank=False)
    mileage = models.IntegerField(null=False, blank=False)
    price = models.FloatField(null=False, blank=False)

    def __str__(self):
        return f"{self.brand} {self.model} ({self.year})"

    class Meta:
        db_table = 'car'
        verbose_name = 'Машина'

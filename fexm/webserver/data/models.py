import sys

try:
    from django.db import models
except Exception:
    print("There was an error loading django modules. Do you have django installed?")
    sys.exit()


# Create your models here.

class Package(models.Model):
    name = models.CharField(max_length=500)
    version = models.CharField(max_length=500, default=None, null=True)


class Binary(models.Model):
    path = models.CharField(max_length=500)
    package = models.ForeignKey(Package, on_delete=models.CASCADE)
    afl_dir = models.CharField(max_length=500)


class Crash(models.Model):
    name = models.CharField(max_length=100, default=None, null=True)
    binary = models.ForeignKey(Binary, on_delete=models.CASCADE)
    parameter = models.CharField(max_length=500)
    exploitability = models.CharField(max_length=500)
    description = models.CharField(max_length=5000, default=None, null=True)
    file_blob = models.BinaryField(default=None)
    execution_output = models.TextField(default=None)

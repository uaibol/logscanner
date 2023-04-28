from django.db import models

# Create your models here.

class Entry(models.Model):

    timestamp = models.DateTimeField(auto_now_add=True)
    sip = models.CharField(max_length=16)
    method = models.CharField(max_length=10)
    uri = models.TextField()
    query = models.TextField
    sport = models.IntegerField()
    username = models.CharField(max_length=256)
    cip = models.CharField(max_length=16)
    useragent = models.TextField()
    referer = models.TextField()
    status = models.TextField()
    substatus = models.TextField()
    win32status = models.TextField()
    timetaken = models.TextField()
    country = models.CharField(max_length=128)


    def __repr__(self) -> str:
        return self.cip
    


class Attack(models.Model):

    entry_id = models.ForeignKey(Entry, on_delete=models.CASCADE)
    ip = models.CharField(max_length=16)
    type = models.CharField(max_length=10)
    country = models.CharField(max_length=128)


    def __repr__(self) -> str:
        return self.ip, self.type


class LogFiles(models.Model):
    name = models.CharField(max_length=255)
    file = models.FileField(null=True, blank=True)
    created_date = models.DateTimeField(auto_now_add=True)
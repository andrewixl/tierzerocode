from django.db import models

# Create your models here.
class Log(models.Model):
    event_code = models.CharField(max_length=4)
    event_type = models.CharField(max_length=50)
    event_group = models.CharField(max_length=50)
    user_level = models.CharField(max_length=50)
    privledged = models.BooleanField(default=True)
    action = models.CharField(max_length=100)
    outcome = models.CharField(max_length=20)
    additional_data = models.CharField(max_length=250)
    user_id = models.CharField(max_length=50)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.event_code + " " + self.action
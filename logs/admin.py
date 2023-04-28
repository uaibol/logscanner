from django.contrib import admin
from .models import Entry, Attack, LogFiles

class EntryAdmin(admin.ModelAdmin):
    list_display = ["username"]

    class Meta:
        model = Entry

class AttackAdmin(admin.ModelAdmin):
    list_display = ["country"]

    class Meta:
        model = Attack

class LogFileAdmin(admin.ModelAdmin):
    list_display = ["name", "created_date"]

admin.site.register(Entry, EntryAdmin)
admin.site.register(Attack, AttackAdmin)
admin.site.register(LogFiles, LogFileAdmin)

from django import forms

class LogFileForm(forms.Form):
    name = forms.CharField(max_length=255)
    file = forms.FileField()
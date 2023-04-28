from django.shortcuts import render, redirect
from .models import Entry, Attack, LogFiles
from django.core.files.storage import FileSystemStorage
from .forms import LogFileForm
#from scanner import scan_log

# Create your views here.

def front_view(request):
    context = {}
    context["title"] = "Front Page!"
    return render(request, 'index.html', context)


def unique_ip_list(request):
    context = {}
    context["title"] = "Unique IP List"
    return render(request, 'unique_ip_list.html', context)

def unique_ip_country_list(request):
    context = {}
    context["title"] = "Unique IP Country List"
    return render(request, 'unique_ip_country_list.html', context)

def attack_list(request):
    context = {}
    context["title"] = "Attack List"
    return render(request, 'attacks_list.html', context)



def model_form_upload(request):
    form = LogFileForm()
    if request.method == 'POST':
        form = LogFileForm(request.POST, request.FILES)
        if form.is_valid():
            log_files = LogFiles()
            log_files.name = form.cleaned_data["name"]
            log_files.file = form.cleaned_data["logFile"]

            log_files.save()
            
            return redirect('uniqueIPList')
    else:
        form = LogFileForm()
    return render(request, 'index.html', {'form': form})



from django.shortcuts import render, redirect
from .models import Entry, Attack, LogFiles
from django.core.files.storage import FileSystemStorage
from .forms import LogFileForm
from django.http import HttpResponse  
from .helper_functions import process_file, attack_process_file


def front_view(request):
    context = {}
    context["title"] = "Front Page!"
    return render(request, 'index.html', context)


def unique_ip_list(request):
    
    context = {}
    context["title"] = "Unique IP List - Бірегей IP тізімі"
    lastfile = LogFiles.objects.latest('created_date')
    file_full_path = "/home/aibars/Documents/workdir/django_projects/logscanner/media/{}".format(lastfile.file)
    fh = open(file_full_path, 'r')
    counter = 0
    context["counter"] = counter
    if fh.mode  == 'r':
        ip_addresses = process_file(file_full_path)
        uni = ip_addresses
        context["content"] = uni
        #print(uni)

    fh.close()

    return render(request, 'unique_ip_list.html', context)

def unique_ip_country_list(request):
    context = {}
    context["title"] = "Unique IP Country List - Бірегей IP және елдер тізімі"
    lastfile = LogFiles.objects.latest('created_date')
    file_full_path = "/home/aibars/Documents/workdir/django_projects/logscanner/media/{}".format(lastfile.file)
    fh = open(file_full_path, 'r')
    counter = 0
    context["counter"] = counter
    if fh.mode  == 'r':
        ip_addresses = process_file(file_full_path)
        uni = ip_addresses
        context["content"] = uni
        #print(uni)

    fh.close()
    return render(request, 'unique_ip_country_list.html', context)

def attack_list(request):
    context = {}
    context["title"] = "Attack List"
    lastfile = LogFiles.objects.latest('created_date')
    file_full_path = "/home/aibars/Documents/workdir/django_projects/logscanner/media/{}".format(lastfile.file)
    fh = open(file_full_path, 'r')
    counter = 0
    context["counter"] = counter
    if fh.mode  == 'r':
        ip_addresses = attack_process_file(file_full_path)
        uni = ip_addresses
        context["content"] = uni
        #print(uni)

    fh.close()
    return render(request, 'attacks_list.html', context)



def model_form_upload(request):
    form = LogFileForm()
    if request.method == 'POST':
        fname = request.POST.get("filename")
        print(fname)
        filepath = request.FILES.get("logFile")
        
        if filepath and fname:
            LogFiles.objects.create(name=fname, file=filepath).save()
            return redirect('uniqueIPList')
        
    else:
        form = LogFileForm()
    return render(request, 'index.html', {'form': form})



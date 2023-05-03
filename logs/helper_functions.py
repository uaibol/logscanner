import re
import geoip2.database
from django.conf import settings

def process_file(file_path):
    ip_country_map = {}
    gl_path = "{}/{}".format(settings.MEDIA_ROOT, "GeoLite2-Country.mmdb")
    reader = geoip2.database.Reader(gl_path)  
    
    with open(file_path, 'r') as file:
        for line in file:
            match = re.search(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            if match:
                ip_address = match.group(1)
                try:
                    response = reader.country(ip_address)
                    country = response.country.name
                    ip_country_map[ip_address] = country
                except geoip2.errors.AddressNotFoundError:
                    ip_country_map[ip_address] = 'Белгісіз'
    
    reader.close()
    return ip_country_map

def attack_process_file(file_path):
    ip_country_map = {}
    gl_path = "{}/{}".format(settings.MEDIA_ROOT, "GeoLite2-Country.mmdb")
    reader = geoip2.database.Reader(gl_path)
    
    excluded_requests = {
        'GET / HTTP/1.1',
        'GET / HTTP/1.0',
        'GET /robots.txt HTTP/1.1',
        'GET /favicon.ico HTTP/1.1',
        'POST / HTTP/1.1',
        'GET /auth HTTP/1.1',
        'GET /ads.txt HTTP/1.1',
        'HEAD / HTTP/1.1',
        'GET /sitemap.xml HTTP/1.1',
        '-e HEAD / HTTP/1.1',
        'PRI * HTTP/2.0',
        'GET favicon.ico HTTP/1.1',
    }
    #excluded_requests.add(re.compile(r'^GET \/v7\/ HTTP\/1\.1'))
    
    with open(file_path, 'rt', encoding='iso-8859-15') as file:
        for line in file:
            if any(request in line for request in excluded_requests):
                continue 
            match = re.search(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            datetime_match = re.search(r'\[(.*?)\]', line)
            uri_match = re.search(r'\"(.*?)\"', line)
            if match and datetime_match and uri_match:
                ip_address = match.group(1)
                datetime_str = datetime_match.group(1)
                uri_str = uri_match.group(1)
                decoded_uri = bytes(uri_str, 'utf-8').decode('unicode-escape')
                query_match = re.search(r'\?(.*)', uri_str)
                query_str = query_match.group(1) if query_match else ''
                decoded_query = bytes(query_str, 'utf-8').decode('unicode-escape')
                try:
                    response = reader.country(ip_address)
                    country = response.country.name
                    country_name = response.country.name
                    ip_country_map[ip_address] = {
                        'ip': ip_address,
                        'country': country,
                        'uri': decoded_uri,
                        'query': decoded_query,
                        'datetime': datetime_str,
                        'is_attack': is_attack(line),
                    }
                  
                except geoip2.errors.AddressNotFoundError:
                     ip_country_map[ip_address] = {
                        'ip': ip_address,
                        'country': 'Белгісіз',
                        'uri': uri_str,
                        'query': query_str,
                        'datetime': datetime_str,
                        'is_attack': is_attack(line),
                    }
                

    reader.close()
    return ip_country_map


def make_regex(patterns):
    return re.compile('|'.join(patterns))


def is_attack(log_line):
    sqli_regex = make_regex([
        '--',                          # sql comment
        '\;',                          # end of statement
        '\/\*', '\*\/',                # block comment
        '(char|concat|cast|eval).*\(', # sql functions
    ])
    
    file_inclusion_regex = make_regex([
        ':\/\/',      # protocol
        '(\.+\/)+',   # path ./ or ../
    ])
    
    webshell_regex = make_regex([
        'cmd=',     # common query parameter
        'passwd',   # password file
        'system32'  # windows system32 directory
        'whoami',   # common command
        '\*\..*',   # file extension e.g. *.php
        '(\.+\/)+', # path ./ or ../
    ])
    
    if sqli_regex.search(log_line):
        return True
    
    if file_inclusion_regex.search(log_line):
        return True
    
    if webshell_regex.search(log_line):
        return True
    
    return False
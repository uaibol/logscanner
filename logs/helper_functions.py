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
                #ip_addresses.add(ip_address)
                try:
                    response = reader.country(ip_address)
                    country = response.country.name
                    ip_country_map[ip_address] = country
                    #print(f"IP Address: {ip_address}, Country: {country}")
                except geoip2.errors.AddressNotFoundError:
                    ip_country_map[ip_address] = 'Белгісіз'

               

    
    reader.close()
    return ip_country_map

def attack_process_file(file_path):
    ip_country_map = {}
    gl_path = "{}/{}".format(settings.MEDIA_ROOT, "GeoLite2-Country.mmdb")
    reader = geoip2.database.Reader(gl_path)
    
    with open(file_path, 'r') as file:
        for line in file:
            match = re.search(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            if match:
                ip_address = match.group(1)
                #ip_addresses.add(ip_address)
                try:
                    response = reader.country(ip_address)
                    country = response.country.name
                    ip_country_map[ip_address] = country
                    #print(f"IP Address: {ip_address}, Country: {country}")
                except geoip2.errors.AddressNotFoundError:
                    ip_country_map[ip_address] = 'Белгісіз'
                
                 # Extract datetime, URI, and query
                datetime_match = re.search(r'\[(.*?)\]', line)
                uri_match = re.search(r'\"(.*?)\"', line)

                if datetime_match and uri_match:
                    datetime_str = datetime_match.group(1)
                    uri_str = uri_match.group(1)
                    
                    # Extract query from URI
                    query_match = re.search(r'\?(.*)', uri_str)
                    query_str = query_match.group(1) if query_match else ''
                    
                    print(f"Datetime: {datetime_str}")
                    print(f"URI: {uri_str}")
                    print(f"Query: {query_str}")
                    #ip_country_map[ip_address] = datetime_str

                if is_attack(line):
                    print(f"Potential attack detected from IP: {ip_address}")
                    attacked_ip_addresses = uri_str + "------" + datetime_str + "Potential attack detected from IP: " + ip_address + " " + country
                    ip_country_map[ip_address] = attacked_ip_addresses

    
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
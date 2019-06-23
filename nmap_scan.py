import json, csv
import os
from xml2csv import *
import socket

def cvedetails(nmap_csv):
    nmap_list = nmap_csv.split("\n")
    for line in nmap_list[1:]:
        if line.split(",")[5] != "" and line.split(",")[6]!="" :
            print(line.split(",")[5]+ " - "+  line.split(",")[6])
        else:
            continue

def singip(ip):
    print(ip)
    n_output = os.popen("nmap -sV -oX nmap.xml "+ip).read()
    nmap_xml = NMAP_XMLParser("nmap.xml")
    nmap_xml.setCSVPath("nmap.csv")
    nmap_xml.dumpCSV()

def ScanIps(listofips): 
    for ip in listofips:
        scan_xml = singip(ip)


njson  = {}
iplist = ['192.168.100.5','192.168.100.45','192.168.100.40','192.168.100.10','192.168.100.153','192.168.100.115']
with open('nmap.csv', 'w') as f:
    csv_header = "IP Address,FQDN,Port,Protocol,Service,Name,Version"
    f.write(csv_header)

ScanIps(iplist)
with open('nmap.csv','r') as f:
    nmap_csv = f.read()
# print(nmap_csv)
cvedetails(nmap_csv)
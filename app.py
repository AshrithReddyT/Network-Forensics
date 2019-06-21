from flask import Flask, request, render_template
import glob
import os
import json

white_list = [{'src': '192.168.100.40'  , 'dst': '192.168.100.115', 'port': '502'},
              {'src': '192.168.100.40', 'dst': '192.168.100.5', 'port' : '502' },
              {'src': '192.168.100.10', 'dst': '192.168.100.5', 'port': '54844'},
              {'src': '192.168.100.10', 'dst': '192.168.100.5', 'port': '58156'},
              {'src': '192.168.100.45', 'dst': '192.168.100.5', 'port': '44818'}
             ]

app = Flask(__name__, static_url_path='/static')

@app.route('/')
def index():
    return render_template('network.html')

@app.route('/live')
def live():
    return render_template('live.html')

@app.route('/viewnode', methods = ['GET'])
def viewnode():
    node = request.args.get('node')
    list_of_files = glob.glob('./logs/events/*.log')
    protocs = {"TCP":0,"UDP":0,"DNS":0,"DHCP":0,"ICMP":0,"ModbusTCP":0,"CIP":0,"IEC104":0,"Others":0}
    latest_file = max(list_of_files, key=os.path.getctime)
    events_lines = []
    with open(latest_file,"r") as f:
        line = f.readline()
        while line:
            src_ip = line.split(",")[1]
            dst_ip = line.split(",")[2]
            # print(ip, node)
            if str(src_ip)==str(node) or str(dst_ip)==str(node):
                events_lines.append(line.split(",")[-2])
            line = f.readline()
    # lines = lines[::-1]
    for line in events_lines:
        if line in protocs.keys():
            protocs[line]+=1
        else:
            protocs["Others"]+=1
    
    for key, value in protocs.items():
        protocs[key] = round((protocs[key]/len(events_lines))*100)
    print(protocs)
    return render_template('viewnode.html', node=node, protocs=protocs)

@app.route('/3d')
def three():
    return render_template('index.html')

@app.route('/lineCharts')
def lineCharts():
    return render_template('lineCharts.html')

@app.route('/pie')
def pie():
    list_of_files = glob.glob('./logs/incidents/*.log') 
    latest_file = max(list_of_files, key=os.path.getctime)
    alert_file = './logs/incidents/alert.csv'
    incidents_lines = []
    malicious_events = {"TCP":0,"UDP":0,"DNS":0,"DHCP":0,"ICMP":0,"ModbusTCP":0,"CIP":0,"IEC104":0,"Others":0}
    normal_events = {"TCP":0,"UDP":0,"DNS":0,"DHCP":0,"ICMP":0,"ModbusTCP":0,"CIP":0,"IEC104":0,"Others":0}
    with open(latest_file,"r") as f:
        line = f.readline()
        while line:
            incidents_lines.append(line.split(",")[-1][:-1])
            line = f.readline()
    with open(alert_file,"r") as f:
        line = f.readline()
        while line:
            words = line.split(',')
            for _ in white_list:
                if words[0] == _['src'] and words[2] == _['dst'] and (words[1] == _['port'] or words[3] == _['port']) or  words[0] == _['src'] and words[2] == _['dst'] and (words[1] == _['port'] or words[3] == _['port']):
                    line = f.readline()
                    words = line.split(',')
                    continue
            # print(words)
            if(words[1] == '502' or words[3] == '502'):
                words[-1] = 'ModbusTCP'
            elif(words[1] == '54844' or words[3] == '54844'):
                words[-1] = 'IEC104'
            elif(words[1] == '44818' or words[3] == '44818'):
                words[-1] = 'CIP'
            inci = words[5]
            incidents_lines.append(inci)
            line = f.readline()
    for line in incidents_lines:
        print(line)
        if line in malicious_events.keys():
            malicious_events[line]+=1
        else:
            malicious_events["Others"]+=1
    
    # malicious_events = malicious_events/len(incidents_lines)
    list_of_files = glob.glob('./logs/events/*.log') 
    latest_file = max(list_of_files, key=os.path.getctime)
    events_lines = []
    with open(latest_file,"r") as f:
        line = f.readline()
        while line:
            events_lines.append(line.split(",")[-2])
            line = f.readline()
    # lines = lines[::-1]
    for line in events_lines:
        if line in normal_events.keys():
            normal_events[line]+=1
        else:
            normal_events["Others"]+=1
    
    try:
        for key, value in malicious_events.items():
            malicious_events[key] = malicious_events[key]/len(incidents_lines)
    except:
        pass
    for key, value in normal_events.items():
        normal_events[key] = normal_events[key]/len(events_lines)
    print(malicious_events)
    print(normal_events)
    return render_template('pie.html', malicious_events=malicious_events, normal_events=normal_events)
    
@app.route('/incidents')
def incidents():
    list_of_files = glob.glob('./logs/incidents/*.log') 
    alert_file = "./logs/incidents/alert.csv"
    latest_file = max(list_of_files, key=os.path.getctime)
    lines = []
    with open(latest_file,"r") as f:
        line = f.readline()
        while line:
            lines.append(line.split(","))
            line = f.readline()
    with open(alert_file,"r") as f:
        line = f.readline()
        while line:
            words = line.split(',')
            for _ in white_list:
                if words[0] == _['src'] and words[2] == _['dst'] and (words[1] == _['port'] or words[3] == _['port']) or  words[0] == _['src'] and words[2] == _['dst'] and (words[1] == _['port'] or words[3] == _['port']):
                    line = f.readline()
                    words = line.split(',')
                    continue
            # print(words)
            if(words[1] == '502' or words[3] == '502'):
                words[-1] = 'ModbusTCP'
            elif(words[1] == '54844' or words[3] == '54844'):
                words[-1] = 'IEC104'
            elif(words[1] == '44818' or words[3] == '44818'):
                words[-1] = 'CIP'
            inci = [words[0], words[2], words[4], words[5]]
            lines.append(inci)
            line = f.readline()
    lines = lines[::-1]
    return render_template('incidents.html', data=lines)

@app.route('/events')
def events():
    list_of_files = glob.glob('./logs/events/*.log') 
    latest_file = max(list_of_files, key=os.path.getctime)
    lines = []
    with open(latest_file,"r") as f:
        line = f.readline()
        while line:
            lines.append(line.split(","))
            line = f.readline()
    lines = lines[::-1]
    return render_template('events.html', data=lines)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port='8000', debug=True)

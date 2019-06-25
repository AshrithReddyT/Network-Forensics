import networkx as nx
import json
from scapy.all import *
import matplotlib.pyplot as plt
import argparse
import pandas as pd 
import datetime
from multiprocessing import Process
from collections import Counter
import os
import time
# from nmap_scan import *
import os
if not os.path.exists("logs"):
    os.makedirs("logs")

if not os.path.exists("logs/events"):
    os.makedirs("logs/events")

if not os.path.exists("logs/incidents"):
    os.makedirs("logs/incidents")

INCIDENTS_LOGFILE = "logs/incidents/incidents-"+str(datetime.datetime.now().date())+'_'+str(datetime.datetime.now().timestamp())+'.log'
EVENTS_LOGFILE = "logs/events/events-"+str(datetime.datetime.now().date())+'_'+str(datetime.datetime.now().timestamp())+'.log'
open(INCIDENTS_LOGFILE,"w").close()
open(EVENTS_LOGFILE,"w").close()
# with open("static/data.log", "w") as f:
#     f.write("timestamp,src,dst,protoc,len\n")

# print(INCIDENTS_LOGFILE)
prev_comm = []
prev_devices = {}


packets = []
def createGraph(dpkts):
    malicious = {}
    global prev_devices
    global prev_comm
    comm_count = {}
    pkts=[]
    max = 0
    for i in dpkts:
        pkts.append(i[1])
    # pkts = rdpcap("CIP.pcapng")
    comm = []
    protoc = []
    devices = {}
    for i, pkt in enumerate(pkts):
        try:
            devices[pkts[i][IP].src] = pkts[i][Ether].src
            devices[pkts[i][IP].dst] = pkts[i][Ether].dst
            comm.append((pkts[i][IP].src, pkts[i][IP].dst))
            if(str(pkts[i][IP].src)+":"+ str(pkts[i][IP].dst) in comm_count.keys()):
                comm_count[str(pkts[i][IP].src)+":"+ str(pkts[i][IP].dst)]+=1
                comm_count[str(pkts[i][IP].dst)+":"+ str(pkts[i][IP].src)]+=1
                if comm_count[str(pkts[i][IP].dst)+":"+ str(pkts[i][IP].src)] > max:
                    max+=1
            else:
                comm_count[str(pkts[i][IP].src)+":"+ str(pkts[i][IP].dst)]=1
                comm_count[str(pkts[i][IP].dst)+":"+ str(pkts[i][IP].src)]=1
            res = list(expand(pkts[i]))
            if(res[-1].name == 'Padding' or res[-1].name == 'Raw'):
                protoc.append(res[-2].name)
            else:
                protoc.append(res[-1].name)
            # print(pkts[i].show())
        except:
            pass

    # ScanIps(devices.keys())    
    with open(INCIDENTS_LOGFILE, 'r') as f:
        line = f.readline()
        while line:
            words = line.split(',')
            malicious[words[0]+":"+words[1]]=1
            malicious[words[1]+":"+words[0]]=1
            line = f.readline()
    G=nx.Graph()
    G.add_nodes_from(devices.keys())
    G.add_edges_from(comm)
    labels = {}
    # for i,c in enumerate(comm):
    #     labels[c] = protoc[i]

    pos = nx.spring_layout(G)

    nx.draw(G,pos,edge_color='black',width=1,linewidths=1, node_size=1000, alpha=0.9, labels={node:node for node in G.nodes()})
    nx.draw_networkx_edge_labels(G, pos, edge_labels=labels,font_color='red')

    if set(comm) == set(prev_comm) and set(devices.keys()) == set(prev_devices.keys()):
        return
    
    all_nodes = list(G.nodes())
    for u in G.edges():
        if u[0]+":"+u[1] not in malicious:
            malicious[u[0]+":"+u[1]] = 0
            malicious[u[1]+":"+u[0]] = 0

    nodes = [{'name': str(i), 'group':int(random.randint(0,100))%2}
            for i in G.nodes()]
    links = [{'source': all_nodes.index(u[0]), 'target': all_nodes.index(u[1]), 'value':malicious[u[0]+":"+u[1]], 'size':comm_count[u[0]+":"+u[1]]/max}
            for u in G.edges()]
    with open('static/graph.json', 'w') as f:
        json.dump({'nodes': nodes, 'links': links}, f, indent=4,)
    
    nodes = [{'id': str(i), 'group':int(random.randint(0,100))%2}
            for i in G.nodes()]
    links = [{'source': u[0], 'target': u[1], 'value':malicious[u[0]+":"+u[1]], 'size':(comm_count[u[0]+":"+u[1]]/max)}
            for u in G.edges()]
    with open('static/graph1.json', 'w') as f:
        json.dump({'nodes': nodes, 'links': links}, f, indent=4,)
    prev_comm = comm
    prev_devices = devices
CACHE = {}
STORE = 'store.h5'  
packets = []
flag = 0
def process_row(d, key, max_len=100, _cache=CACHE):
    lst = _cache.setdefault(key, [])
    if len(lst) >= max_len:
        store_and_clear(lst, key)
    lst.append(d)

def store_and_clear(lst, key):
    global flag
    df = pd.DataFrame(lst)
    with open(EVENTS_LOGFILE, "a") as f , open("static/data.log", "w") as f1:
        f1.write("timestamp,src,dst,protoc,len\n")
        for index, row in df.iterrows():
            # print(row['c1'], row['c2'])'
            f.write(str(row['Time_Stamp'])+","+row['Source_IP']+","+row['Destination_IP']+","+row['protocol']+","+str(row['length'])+"\n")
            
            f1.write(str(row['Time_Stamp'])+","+row['Source_IP']+","+row['Destination_IP']+","+row['protocol']+","+str(row['length'])+"\n")
    lst.clear()

Previous_TCP = []
Previous_UDP = []
Previous_DNS = []
Previous_DHCP = []
Other = []

flags = {
    'F': 'FIN',
    'S': 'SYN',
    'R': 'RST',
    'P': 'PSH',
    'A': 'ACK',
    'U': 'URG',
    'E': 'ECE',
    'C': 'CWR',
}
class Attacks():
    def __init__(self):
        self.DOS()
        self.DDOS()

    def DOS(self):
        IPs = {}
        first_packet = {}
        last_packet = {}
        for pkt in packets:
            res = list(expand(pkt[1]))
            if(res[-1].name == 'Padding' or res[-1].name == 'Raw'):
                protoc = res[-2].name
            else:
                protoc = res[-1].name
            # f = [flags[x] for x in pkt[1].sprintf('%TCP.flags%')]
            if pkt[1].haslayer(Raw) and pkt[1].haslayer(TCP):
                if str(pkt[1][IP].src)+':'+str(pkt[1][IP].dst)+':'+str(protoc) in IPs:
                    IPs[str(pkt[1][IP].src)+':'+str(pkt[1][IP].dst)+':'+str(protoc)]+=1
                    last_packet[str(pkt[1][IP].src)+':'+str(pkt[1][IP].dst)+':'+str(protoc)] = pkt[0]
                else:
                    IPs[str(pkt[1][IP].src)+':'+str(pkt[1][IP].dst)+':'+str(protoc)]=1
                    first_packet[str(pkt[1][IP].src)+':'+str(pkt[1][IP].dst)+':'+str(protoc)] = pkt[0]
                    last_packet[str(pkt[1][IP].src)+':'+str(pkt[1][IP].dst)+':'+str(protoc)] = pkt[0]
        
        # print(IPs, first_packet, last_packet)
        for ip in IPs.keys():
            if(last_packet[ip] != first_packet[ip]):
                # print((IPs[ip]/(last_packet[ip] - first_packet[ip]).total_seconds()))
                if (IPs[ip]/(last_packet[ip] - first_packet[ip]).total_seconds())>25 and (last_packet[ip] - first_packet[ip]).total_seconds()>=1:
                    ips = ip.split(':')
                    # print(ips)
                    log = ips[0]+","+ips[1]+",Denial of service(DOS) Attempt,"+ips[2]+"\n"
                    with open(INCIDENTS_LOGFILE, 'a+') as f:
                        for line in f:
                            if log in line:
                                break
                        else:
                            f.write(log)

    def DDOS(self):
        IPs = {}
        first_packet = {}
        last_packet = {}
        for pkt in packets:
            res = list(expand(pkt[1]))
            if(res[-1].name == 'Padding' or res[-1].name == 'Raw'):
                protoc = res[-2].name
            else:
                protoc = res[-1].name
            if pkt[1].haslayer(Raw) and pkt[1].haslayer(TCP):
            # f = [flags[x] for x in pkt[1].sprintf('%TCP.flags%')]
                if str(pkt[1][IP].dst)+':'+str(protoc) in IPs:
                    IPs[str(pkt[1][IP].dst)+':'+str(protoc)]+=1
                    last_packet[str(pkt[1][IP].dst)+':'+str(protoc)] = pkt[0]
                else:
                    IPs[str(pkt[1][IP].dst)+':'+str(protoc)]=1
                    first_packet[str(pkt[1][IP].dst)+':'+str(protoc)] = pkt[0]
                    last_packet[str(pkt[1][IP].dst)+':'+str(protoc)] = pkt[0]
        
        # print(IPs, first_packet, last_packet)
        for ip in IPs.keys():
            if(last_packet[ip] != first_packet[ip]):
                # print((IPs[ip]/(last_packet[ip] - first_packet[ip]).total_seconds()))
                if (IPs[ip]/(last_packet[ip] - first_packet[ip]).total_seconds())>50 and (last_packet[ip] - first_packet[ip]).total_seconds()>=1 : 
                    ips = ip.split(':')
                    log = "Multiple IPs,"+ips[0]+",Distributed Denial of service (DDOS) Attempt,"+ips[1]+"\n"
                    with open(INCIDENTS_LOGFILE, 'a+') as f:
                        for line in f:
                            if log in line:
                                break
                        else:
                            f.write(log)


class TCP_Attacks():
    def __init__(self):
        self.SYN_Flood_Direct()
        self.SYN_Flood_DDOS()

    def SYN_Flood_Direct(self):
        IPs = {}
        first_packet = {}
        last_packet = {}
        for pkt in Previous_TCP:
            # f = [flags[x] for x in pkt[1].sprintf('%TCP.flags%')]
            if 'S' == str(pkt[1][TCP].flags):
                if str(pkt[1][IP].src)+':'+str(pkt[1][IP].dst) in IPs:
                    IPs[str(pkt[1][IP].src)+':'+str(pkt[1][IP].dst)]+=1
                    last_packet[str(pkt[1][IP].src)+':'+str(pkt[1][IP].dst)] = pkt[0]
                else:
                    IPs[str(pkt[1][IP].src)+':'+str(pkt[1][IP].dst)]=1
                    first_packet[str(pkt[1][IP].src)+':'+str(pkt[1][IP].dst)] = pkt[0]
                    last_packet[str(pkt[1][IP].src)+':'+str(pkt[1][IP].dst)] = pkt[0]
        
        # print(IPs, first_packet, last_packet)
        for ip in IPs.keys():
            if(last_packet[ip] != first_packet[ip]):
                if (IPs[ip]/(last_packet[ip] - first_packet[ip]).total_seconds()>250) and (last_packet[ip] - first_packet[ip]).total_seconds()>=1:
                    ips = ip.split(':')
                    log = ips[0]+","+ips[1]+",SYN FLOODING(Direct),TCP\n"
                    with open(INCIDENTS_LOGFILE, 'a+') as f:
                        for line in f:
                            if log in line:
                                break
                        else:
                            f.write(log)
        
    def SYN_Flood_DDOS(self):
        # time.sleep(1)
        pass

class Parser:

    fragged = 0
    oldmheaders = []
    prev_pkt = {80:{}}

    def pkt_sorter(self, pkt):
        if pkt.haslayer(Raw) and pkt.haslayer(TCP):
            self.dest    = pkt[IP].dst
            self.src     = pkt[IP].src
            self.dport   = pkt[TCP].dport
            self.sport   = pkt[TCP].sport
            self.ack     = pkt[TCP].ack
            self.seq     = pkt[TCP].seq
            self.load    = str(pkt[Raw].load)

            if self.dport == 80 or self.sport == 80:
                """ HTTP """
                port = 80
                # Catch fragmented pkts
                self.header_lines = self.hb_parse(port)
                return self.http_parser(port)


    def headers_body(self, protocol):
        try:
            h, b = protocol.split("\r\n\r\n", 1)
            return h, b
        except Exception:
            h, b = protocol, ''
            return h, b

    def frag_joiner(self, port):
        self.fragged = 0
        if len(self.prev_pkt[port]) > 0:
            if self.ack in self.prev_pkt[port]:
                self.fragged = 1
                return {self.ack:self.prev_pkt[port][self.ack]+self.load}
        return {self.ack:self.load}

    def hb_parse(self, port):
        self.prev_pkt[port] = self.frag_joiner(port)
        self.headers, self.body = self.headers_body(self.prev_pkt[port][self.ack])
        return self.headers.split('\r\n')

    def http_parser(self, port):

        url = None
        host = self.search_headers('host: ')
        if host:
            get = self.search_headers('get /')
            post = self.search_headers('post /')
            if get:
                url = host+get
            elif post:
                url = host+post
        else:
            return

        self.http_user_pass(host, port)

    def http_user_pass(self, host, port):
        user_regex = '([Ee]mail|[Uu]ser|[Uu]sername|[Nn]ame|[Ll]ogin|[Ll]og|[Ll]ogin[Ii][Dd])=([^&|;]*)'
        pw_regex = '([Pp]assword|[Pp]ass|[Pp]asswd|[Pp]wd|[Pp][Ss][Ww]|[Pp]asswrd|[Pp]assw)=([^&|;]*)'
        username = re.findall(user_regex, self.body)
        password = re.findall(pw_regex, self.body)
        user = None
        pw = None

        if username:
            for u in username:
                user = u[1]
                break

        if password:
            for p in password:
                if p[1] != '':
                    pw = p[1]
                    break

        if user or pw:
            with open(INCIDENTS_LOGFILE, 'a+') as f:
                log = str(self.src)+','+str(host)+','+'HTTP Login Attempt USER: '+user+' PASS: '+ pw+','+'HTTP\n'
                f.write(log)
            self.dest = host


    def search_headers(self, header):
        for l in self.header_lines:
            if header in l.lower():
                line = l.split()
                try:
                    return line[1]
                except Exception:
                    return 0


def expand(x):
    yield x
    while x.payload:
        x = x.payload
        yield x

def headers_body(self, protocol):
    try:
        h, b = protocol.split("\r\n\r\n", 1)
        return h, b
    except Exception:
        h, b = protocol, ''
        return h, b

def hb_parse(self, port):
    self.prev_pkt[port] = self.frag_joiner(port)
    self.headers, self.body = self.headers_body(self.prev_pkt[port][self.ack])
    return self.headers.split('\r\n')

ftpuser = None
def ftp(pkt):
    global ftpuser
    dest    = pkt[IP].dst
    src     = pkt[IP].src
    dport   = pkt[TCP].dport
    sport   = pkt[TCP].sport
    load    = pkt[Raw].load
    load = load.decode('utf-8')    
    load = load.replace('\n','')
    load = load.replace('\r','')
    # print(load)
    if 'USER ' in load:
        user = load.strip('USER ')
        ftpuser = user

    elif 'PASS ' in load:
        pw = load.strip('PASS ')
        with open(INCIDENTS_LOGFILE, 'a+') as f:
            log = str(src)+','+str(dest)+','+'FTP Login Attempt USER: '+str(ftpuser)+'PASS: '+ str(pw)+','+'FTP\n'
            f.write(log)
            ftpuser=None
    
    if 'authentication failed' in load:
            resp = load
            with open(INCIDENTS_LOGFILE, 'a+') as f:
                log = str(src)+','+str(dest)+','+'FTP response: '+str(resp)+','+'FTP\n'
                f.write(log)

    if '230 OK' in load:
        resp = load
        with open(INCIDENTS_LOGFILE, 'a+') as f:
            log = str(src)+','+str(dest)+','+'FTP response: '+str(resp)+','+'FTP\n'
            f.write(log)
            # f.DOS()
            
i = 0
def processPkt(pkt):
	# print("lol")
    if pkt.haslayer(Raw) and pkt.haslayer(TCP):
        dport   = pkt[TCP].dport
        sport   = pkt[TCP].sport
        # print(dport, sport)
        load    = str(pkt[Raw].load)
        if dport == 21 or sport == 21:
            port = 21
            # print(pkt)
            ftp(pkt)
        elif dport == 80 or sport == 80:
            parser = Parser()
            parser.pkt_sorter(pkt)

    global i
    i+=1
    if i%100==0:
        print(str(i)+" packets captured")
    try:
        if len(packets)%100==0:
            createGraph(packets)
        # print(len(packets))
        if len(packets)>=1000:
            del packets[:100]
				
        packets.append([datetime.datetime.now(), pkt])
		# print(len(packets))
			
        if IP in pkt:
            if i%10==0:
                t = Attacks()
            res = list(expand(pkt))
            if(res[-1].name == 'Padding' or res[-1].name == 'Raw'):
                protoc = res[-2].name
            else:
                protoc = res[-1].name

            if(protoc == 'TCP'):
                if(len(Previous_TCP)>=1000):
                    del Previous_TCP[:100]
					
                Previous_TCP.append([datetime.datetime.now(), pkt])
                if i%10==0:
                    t = TCP_Attacks()
            elif(protoc == 'UDP'):
                if(len(Previous_UDP)>=1000):
                    del Previous_UDP[:100]
                Previous_UDP.append([datetime.datetime.now(), pkt]) 
            elif(protoc == 'DNS'):
                if(len(Previous_DNS)>=1000):
                    del Previous_DNS[:100]
                Previous_DNS.append([datetime.datetime.now(), pkt]) 
            elif(protoc == 'DHCP'):
                if(len(Previous_UDP)>=1000):
                    del Previous_DHCP[:100]
                Previous_DHCP.append([datetime.datetime.now(), pkt])    
            else:
                if(len(Other)>=1000):
                    del Other[:100]
                Other.append([datetime.datetime.now(), pkt])
			# print(datetime.datetime.now(), pkt[IP].src, pkt[IP].dst, protoc, pkt.summary())
            process_row({'Time_Stamp': datetime.datetime.now(), 'Source_IP': pkt[IP].src, 'Destination_IP': pkt[IP].dst, 'protocol':protoc, 'length': len(pkt)}, key="df")
    except KeyboardInterrupt:
        for k, lst in CACHE.items(): 
            store_and_clear(lst, k)
        with pd.HDFStore(STORE) as store:
            df = store["df"]   
        quit()

def main():
	print("Started Sniffing...")
	sniff(store=True, prn=processPkt)

main()
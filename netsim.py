import networkx as nx
import json
from scapy.all import *
import modbus, cip, iec
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

# print(INCIDENTS_LOGFILE)
prev_comm = []
prev_devices = {}


packets = []
def createGraph(pkts):
    malicious = {}
    global prev_devices
    global prev_comm
    comm_count = {}
    max = 0
    # pkts = rdpcap("Modbus_TCP.pcapng")
    comm = []
    protoc = []
    devices = {}
    for i, pkt in enumerate(pkts):
        try:
            # print(pkt.show())
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
yData=[]
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
                if (IPs[ip]/(last_packet[ip] - first_packet[ip]).total_seconds()>15):
                    ips = ip.split(':')
                    log = ips[0]+","+ips[1]+",SYN FLOODING(Direct),TCP\n"
                    with open(INCIDENTS_LOGFILE, 'r+') as f:
                        for line in f:
                            if log in line:
                                break
                        else:
                            f.write(log)
        
    def SYN_Flood_DDOS(self):
        # time.sleep(1)
        pass
def expand(x):
    yield x
    while x.payload:
        x = x.payload
        yield x

i = 0
def processPkt(pkt):
	# print("lol")
	global i
	i+=1
	if i%100==0:
		print(str(i)+" packets captured")
	try:
		if len(packets)%100==0:
			createGraph(packets)
		if len(packets)>=1000:
			del packets[:100]
				
		packets.append(pkt)
		# print(len(packets))
			
		if IP in pkt:
			yData.append(pkt[IP].len)
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

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
LOGFILE = "logs/"+str(datetime.datetime.now().date())+'_'+str(datetime.datetime.now().timestamp())+'.log'
open(LOGFILE,"w").close()


print(LOGFILE)
prev_comm = []
prev_devices = {}


packets = []
def createGraph(pkts):
    global prev_devices
    global prev_comm
    comm_count = {}
    max = 0
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
    nodes = [{'name': str(i), 'group':int(random.randint(0,100))%2}
            for i in G.nodes()]
    links = [{'source': all_nodes.index(u[0]), 'target': all_nodes.index(u[1]), 'value':int(random.randint(0,100))%2, 'size':comm_count[u[0]+":"+u[1]]/max}
            for u in G.edges()]
    with open('static/graph.json', 'w') as f:
        json.dump({'nodes': nodes, 'links': links}, f, indent=4,)
    prev_comm = comm
    prev_devices = devices
CACHE = {}
STORE = 'store.h5'  
packets = []
yData=[]
def process_row(d, key, max_len=5000, _cache=CACHE):
    lst = _cache.setdefault(key, [])
    if len(lst) >= max_len:
        store_and_clear(lst, key)
    lst.append(d)

def store_and_clear(lst, key):
    df = pd.DataFrame(lst)
    with pd.HDFStore(STORE,mode='w') as store:
        store.append(key, df, data_columns = ['Source IP','Destination IP','protocol'], max_itemsize = { 'protocol' : 50})
        
        print(store.get_storer('df').table)
        
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
                if (IPs[ip]/(last_packet[ip] - first_packet[ip]).total_seconds()>5):
                    ips = ip.split(':')
                    log = "Attacker: "+ips[0]+" Victim: "+ips[1]+" Possible Attack: SYN FLOODING(Direct)\n"
                    with open(LOGFILE, 'r+') as f:
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
			packets.pop(0)
				
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
					Previous_TCP.pop(0)
					
				Previous_TCP.append([datetime.datetime.now(), pkt])
				if i%10==0:
					t = TCP_Attacks()
			elif(protoc == 'UDP'):
				if(len(Previous_UDP)>=1000):
					Previous_UDP.pop(0)
				Previous_UDP.append([datetime.datetime.now(), pkt]) 
			elif(protoc == 'DNS'):
				if(len(Previous_DNS)>=1000):
					Previous_DNS.pop(0)
				Previous_DNS.append([datetime.datetime.now(), pkt]) 
			elif(protoc == 'DHCP'):
				if(len(Previous_UDP)>=1000):
					Previous_DHCP.pop(0)
				Previous_DHCP.append([datetime.datetime.now(), pkt])    
			else:
				if(len(Other)>=1000):
					Other.pop(0)
				Other.append([datetime.datetime.now(), pkt])
			# print(datetime.datetime.now(), pkt[IP].src, pkt[IP].dst, protoc, pkt.summary())
			process_row({'Time_Stamp': datetime.datetime.now(), 'Source_IP': pkt[IP].src, 'Destination_IP': pkt[IP].dst, 'protocol':protoc}, key="df")
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
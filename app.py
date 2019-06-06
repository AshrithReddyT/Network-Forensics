from flask import Flask, request, render_template
import glob
import os
import json

app = Flask(__name__, static_url_path='/static')

@app.route('/')
def index():
    with open('./static/graph.json') as json_file:
        data = json.load(json_file)
        links = data['links']
        nodes = data['nodes']
        unsafe_links = len([x for x in links if x['value']==1])
        unsafe_nodes = len([x for x in nodes if x['group']==0])
        
        nodes = len(nodes)
        links = len(links)
        safe_nodes = nodes - unsafe_nodes
        safe_links = links - unsafe_links
    return render_template('network.html', links = links, nodes = nodes, unsafe_links= unsafe_links, unsafe_nodes = unsafe_nodes, safe_links = safe_links, safe_nodes = safe_nodes)

@app.route('/viewnode', methods = ['GET'])
def viewnode():
    node = request.args.get('node')
    return render_template('viewnode.html', node=node)

@app.route('/3d')
def three():
    return render_template('index.html')
    
@app.route('/incidents')
def incidents():
    list_of_files = glob.glob('./logs/incidents/*.log') 
    latest_file = max(list_of_files, key=os.path.getctime)
    lines = []
    with open(latest_file,"r") as f:
        line = f.readline()
        while line:
            lines.append(line.split(","))
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
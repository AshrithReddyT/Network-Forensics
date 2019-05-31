from flask import Flask, request, render_template
import glob
import os

app = Flask(__name__, static_url_path='/static')

@app.route('/')
def index():
    return render_template('network.html')

@app.route('/events')
def events():
    list_of_files = glob.glob('./logs/*.log') # * means all if need specific format then *.csv
    latest_file = max(list_of_files, key=os.path.getctime)
    lines = []
    with open(latest_file,"r") as f:
        line = f.readline()
        while line:
            lines.append(line.split(","))
            line = f.readline()
    return render_template('events.html', data=lines)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port='8000', debug=True)
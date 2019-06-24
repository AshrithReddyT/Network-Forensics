#snort -be -c /etc/snort/snort.conf &
while true; do 
	sleep(10)
	rm /home/gyeyosi/Desktop/learn/summer2019/network_visualisation/develop/Network-Forensics/logs/incidents/alert.csv
	touch /home/gyeyosi/Desktop/learn/summer2019/network_visualisation/develop/Network-Forensics/logs/incidents/alert.csv
done

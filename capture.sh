
#Start Capture
sudo tcpdump -i ens18 -w out.pcap
sudo nfpcapd -l dir -r out.pcap
sudo nfdump -r dir/nfcapd.{whatever} | awk 'BEGIN { OFS=","; } NR > 1 && !/^[A-Z]/ { print $1, $2, $5, $6, $8, $12, $13}' > netflow.csv
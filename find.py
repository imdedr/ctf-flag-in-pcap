import pyshark, re, sys

if len(sys.argv) != 3:
    print "python", sys.argv[0], '"filename"', '"flag pattern"'
    sys.exit(1)

#flag_pattern = "[0-9A-Za-z]+-[0-9A-Za-z]+-[0-9A-Za-z]+-[0-9A-Za-z]+-[0-9A-Za-z]+"
flag_pattern = sys.argv[2]
flag_comp = re.compile( flag_pattern )

pkt_seq = {}
seq_list = []

#cap = pyshark.FileCapture('pcap/20160717105219.pcap')
cap = pyshark.FileCapture(sys.argv[1])

total_pkt = 0
for p in cap:
	if p.transport_layer == "TCP":
		if not p.tcp.stream in pkt_seq:
			pkt_seq.setdefault( p.tcp.stream, [] )
			seq_list.append( p.tcp.stream )
		pkt_seq[p.tcp.stream].append(total_pkt)
	total_pkt += 1

print "Total:", total_pkt, "pkts"

for seq in seq_list:
	found_flag = False
	pkt_buff = ""
	for pkt in pkt_seq[str(seq)]:
		if "data" in cap[pkt]:
			try:
				pkt_buff += cap[pkt].data.data.decode('hex')
				if flag_comp.findall( cap[pkt].data.data.decode('hex') ) != []:
					print "Pkt", pkt+1, ":", flag_comp.findall( cap[pkt].data.data.decode('hex') )[0]
					found_flag = True
			except:
				pass
	if found_flag:
		print "*" * 12, "Start:", seq, "*" *12
		print pkt_buff
		print "*" * 12, "End:", seq, "*" *12

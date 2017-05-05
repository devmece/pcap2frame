# pcap2frame
Converts a PCAP file to a PANDAS or SFRAME data frame

### Requirements
Tshark<br>
PANDAS<br>
SFRAME (optional)<br>

This script creates a dataframe out of the PCAP for the specified protocol.

pcap2frame.py --h<br>
usage: pcap2frame.py [-h] --pcap PCAP --protocol PROTOCOL [--utc] [--sframe]<br>
<br>
optional arguments:<br>
  -h, --help           show this help message and exit<br>
  --pcap PCAP          input file<br>
  --protocol PROTOCOL  tcp,udp,icmp or ipv6<br>
  --utc                convert timestamps to UTC<br>
  --sframe             PANDAS (default) or SFRAME<br>

### Example Usage
pcap2frame.py --pcap UDP_53413.PCAP --protocol udp<br>
2017-05-04 22:26:16 Processing: UDP_53413.PCAP<br>
2017-05-04 22:26:19 Creating: UDP_53413_UDP.PANDAS<br>

### Dataframe Columns
[u'protocol', u'source_ip', u'source_port', u'dest_ip', u'dest_port', u'frame_length', u'info', u'date', u'time']

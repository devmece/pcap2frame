#! /usr/bin/env python

""" 
    Name:   Pcap2Frame
    Author: Ramece Cave
    Email:  rrcave@n00dle.org
    
    License: BSD
    
    Copyright (c) 2016 Ramece Cave
    All rights reserved.
    Redistribution and use in source and binary forms, with or without modification, are permitted      
    provided that the following conditions are met:
    Redistributions of source code must retain the above copyright notice, this list of conditions 
    and the following disclaimer. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the documentation and/or other
    materials provided with the distribution.
    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
    IMPLIED WARRANTIES,INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
    FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
    CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
    DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
    LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF 
    LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH 
    DAMAGE.
"""

from dateutil import parser
from datetime import datetime
import csv,argparse,time,os

#lambdas
dat = lambda: time.strftime("%Y-%m-%d %H:%M:%S")
date2epoch = lambda x: int(time.mktime(parser.parse(x).timetuple()))
getUtc = lambda x: datetime.utcfromtimestamp(x)

protocolFields = {
        "tcp" : ['frame','protocol','source_ip','source_port','dest_ip',\
        'dest_port','frame_length','tcp_flag','date','time'],

        "udp" : ['frame','protocol','source_ip','source_port','dest_ip',\
        'dest_port','frame_length','info','date','time'],

        "icmp" : ['frame','protocol','source_ip','dest_ip','icmp_type',\
        'icmp_code','icmp_ident','frame_length','date','time','icmp_seq_be','icmp_seq_le'],

        "ipv6" : ['frame','protocol','source_ip','dest_ip','frame_length'\
        ,'source_port','dest_port','ipv6_source_ip','ipvs_dst_ip','date','time']
        }

tsharkCmds = {
        "tcp" : 'tshark -tud -n -r %s -T fields -e frame.number -e ip.proto -e frame.time -e \
        ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e frame.len -e tcp.flags tcp and not "(ipv6 or icmp)" > %s',

        "udp" : 'tshark -tud -n -r %s -T fields -e frame.number -e ip.proto -e frame.time -e \
        ip.src -e udp.srcport -e ip.dst -e udp.dstport -e frame.len -e col.Info udp and not "(ipv6 or icmp)" > %s',

        "icmp" : 'tshark -tud -n -r %s -T fields -e frame.number -e ip.proto -e frame.time -e \
        ip.src -e ip.dst -e icmp.type -e icmp.code -e icmp.ident -e icmp.seq -e frame.len icmp and not "(ipv6 or tcp or udp)" > %s',

        "ipv6" : 'tshark -tud -n -r %s -T fields -e frame.number -e ip.proto -e frame.time -e \
        ip.src -e ip.dst -e frame.len -e udp.srcport -e udp.dstport -e ipv6.src -e ipv6.dst ipv6 > %s'
        }

def ExtractPcapData(pcap,protocol):
    print dat(),"Processing:",pcap

    outputFileName = "%s_%s.txt" % (pcap.split(".")[0],protocol.upper())
    tsharkBaseCmd = tsharkCmds.get(protocol)
    # import pdb ; pdb.set_trace()
    execTsharkCmd = tsharkBaseCmd % (pcap,outputFileName)
    b = os.popen(execTsharkCmd).read()

    return outputFileName

def CreateCsv(outputFileName,protocol,convertTime):
    csvEntry = {}

    data = open(outputFileName,"r").read().strip().split("\n")
    csvFileName = outputFileName.replace(".txt",".csv")
    csvFields = protocolFields.get(protocol)

    # print dat(),"Creating:",csvFileName

    with open(csvFileName,"w") as csvfile:
        writer = csv.DictWriter(csvfile,fieldnames=csvFields) #modeline for automation
        writer.writeheader()

        for entry in data:
            entry = entry.split('\t')
            try:
                timestamp = parser.parse(entry[2].split('.')[0]).strftime("%Y-%m-%d %H:%M:%S")
            except:
                import pdb ; pdb.set_trace()

            if convertTime:
                timestamp = str(getUtc(date2epoch(timestamp))) #Convert timestamp to UTC to match alerts
            else: #Test this code, 
                pass

            eventDate,eventTime = timestamp.split()
            del entry[2]
            entry.append(eventDate)
            entry.append(eventTime)

            if protocol == "icmp":
                try:
                    seqBE,seqLE = entry[-5].split(',')
                except:
                    seqBE,seqLE = ("NA","NA")

                del entry[-5] #ICMP
                entry.append(seqBE) #ICMP
                entry.append(seqLE) #ICMP

            csvEntry = dict(zip(csvFields,entry)) #mode line for automation
            writer.writerow(csvEntry)

    return csvFileName

def CreateDataFrame(csvFileName,protocol,sframe):
    if sframe:
        import sframe

        frameName = csvFileName.replace(".csv","_SFRAME")
        dataframe = sframe.SFrame(csvFileName) #create dataframe in SFrame
        dataframe.save(frameName) #save sframe
        print dat(),"Creating SFRAME:",frameName
    else:
        import pandas

        frameName = csvFileName.replace(".csv",".PANDAS")
        pDataframe = pandas.DataFrame.from_csv(csvFileName) #create pandas dataframe
        pDataframe.to_pickle(frameName) #save pandas dataframe
        print dat(),"Creating:",frameName

def main():
    aParser = argparse.ArgumentParser()
    aParser.add_argument("--pcap",help="input file",required=True)
    aParser.add_argument("--protocol",help="tcp,udp,icmp or ipv6",required=True)
    aParser.add_argument("--utc",help="convert timestamps to UTC",required=False,action="store_true")
    aParser.add_argument("--sframe",help="PANDAS (default) or SFRAME",required=False,action="store_true")

    args = aParser.parse_args()
    pcap = args.pcap
    protocol = args.protocol
    convertTime = args.utc
    sframe = args.sframe

    outputFileName = ExtractPcapData(pcap,protocol)
    csvFileName = CreateCsv(outputFileName,protocol,convertTime)
    CreateDataFrame(csvFileName,protocol,sframe)

    os.remove(outputFileName) #clean up extracted data
    os.remove(csvFileName)

if __name__=='__main__':
    main()

#END

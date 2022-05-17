import pandas as pd
import numpy as np
from scapy.all import *

def pcap_label_to_df(csv_file):
    df = pd.read_csv(csv_file)
    return df

def find_pcap(folder):
    for file in os.listdir(folder):
        if os.path.splitext(file)[1] == '.pcap':
            if str.find(file, '2018') != -1 or str.find(file, '2019') != -1:
                return os.path.join(folder, file)
            
def pcap_to_df(pcap_file, df, byline = True):
    
    print("[*] Loading:{0}".format(pcap_file), end = "\r")    
    
    if byline == True:
        packets = PcapReader(pcap_file)
        length = "Unknown"
    else:
        packets = rdpcap(pcap_file)
        length = len(packets)
    print("[+] Load Completed:{0}".format(pcap_file))
    
    pcap_row_id = 0
    i = 0
    df['ts'] = np.nan
    df['ip_version'] = np.nan
    df['ip_ihl'] = np.nan
    df['ip_tos'] = np.nan
    df['ip_len'] = np.nan
    df['ip_id'] = np.nan
    df['ip_flags'] = np.nan
    df['ip_frag'] = np.nan
    df['ip_ttl'] = np.nan
    df['ip_proto'] = np.nan
    df['ip_chksum'] = np.nan
    df['ip_src'] = np.nan
    df['ip_dst'] = np.nan
    df['ip_proto']   = np.nan
    df['tcp_sport']  = np.nan
    df['tcp_dport']  = np.nan
    df['tcp_seq']  = np.nan
    df['tcp_ack']  = np.nan
    df['tcp_dataofs']  = np.nan
    df['tcp_reserved']  = np.nan
    df['tcp_flags']  = np.nan
    df['tcp_window']  = np.nan
    df['tcp_chksum']  = np.nan
    df['tcp_urgptr']  = np.nan
    df['tcp_sport']  = np.nan
    df['udp_sport']  = np.nan
    df['udp_dport']  = np.nan
    df['udp_len']    = np.nan
    df['udp_chksum'] = np.nan
    df['icmp_type'] = np.nan
    df['icmp_code'] = np.nan
    df['icmp_chksum'] = np.nan
    df['icmp_reserved'] = np.nan
    df['icmp_length'] = np.nan
    df['icmp_nexthopmtu'] = np.nan
    df['icmp_unused'] = np.nan
    for p in packets:
        if i == df.shape[0]:
            break
        if pcap_row_id == df['pcap_row_id'][i]:
            df['ts'][i] = p.time
            # p.show()
            if p.haslayer("IP"):
                # a = p['IP'].fields
                df['ip_version'][i] = p['IP'].version
                df['ip_ihl'][i] = p['IP'].ihl
                df['ip_tos'][i] = p['IP'].tos
                df['ip_len'][i] = p['IP'].len
                df['ip_id'][i] = p['IP'].id            
                df['ip_flags'][i] = p['IP'].flags
                df['ip_frag'][i] = p['IP'].frag
                df['ip_ttl'][i] = p['IP'].ttl
                df['ip_proto'][i] = p['IP'].proto
                df['ip_chksum'][i] = p['IP'].chksum
                df['ip_src'][i] = p['IP'].src
                df['ip_dst'][i] = p['IP'].dst
                df['ip_proto'][i]   = p['IP'].proto         
            if p.haslayer("TCP"):
                # t = p['TCP'].fields
                df['tcp_sport'][i]  = p['TCP'].sport
                df['tcp_dport'][i]  = p['TCP'].dport
                df['tcp_seq'][i]  = p['TCP'].seq
                df['tcp_ack'][i]  = p['TCP'].ack
                df['tcp_dataofs'][i]  = p['TCP'].dataofs
                df['tcp_reserved'][i]  = p['TCP'].reserved
                df['tcp_flags'][i]  = p['TCP'].flags
                df['tcp_window'][i]  = p['TCP'].window
                df['tcp_chksum'][i]  = p['TCP'].chksum
                df['tcp_urgptr'][i]  = p['TCP'].urgptr
                df['tcp_sport'][i]  = p['TCP'].sport
            if p.haslayer("UDP"):
                # u = p['UDP'].fields
                df['udp_sport'][i]  = p['UDP'].sport
                df['udp_dport'][i]  = p['UDP'].dport
                df['udp_len'][i]    = p['UDP'].len
                df['udp_chksum'][i] = p['UDP'].chksum
            if p.haslayer("ICMP"):
                c = p['ICMP'].fields
                df['icmp_type'][i]  = p['ICMP'].type
                df['icmp_code'][i]  = p['ICMP'].code
                df['icmp_chksum'][i]  = p['ICMP'].chksum
                df['icmp_reserved'][i]  = p['ICMP'].reserved
                df['icmp_length'][i]  = p['ICMP'].length
                df['icmp_nexthopmtu'][i]  = p['ICMP'].nexthopmtu
                df['icmp_unused'][i]  = p['ICMP'].unused
            
            print("[*] Prasing Progress:{0}/{1}".format(i,length), end = "\r")
            i += 1
            
        pcap_row_id += 1
        
    return df

location = '/Volumes/Unicorn/IoTScenarios/'
folder_list = ['CTU-IoT-Malware-Capture-3-1/',
'CTU-IoT-Malware-Capture-8-1/',
'CTU-IoT-Malware-Capture-20-1/',
'CTU-IoT-Malware-Capture-21-1/',
'CTU-IoT-Malware-Capture-34-1/',
'CTU-IoT-Malware-Capture-42-1/']

folder_list = ['CTU-IoT-Malware-Capture-8-1/']

for folder in folder_list:
    folder = location + folder

    pcap_label_df = pd.read_csv(folder + 'pcap_label.csv')
    pcap_label_df.columns=['pcap_row_id','detailed_label']
    pcap_label_df = pcap_label_df[pcap_label_df['detailed_label'].notnull()]
    pcap_label_df = pcap_label_df.reset_index(drop=True)
    
    pcap_detail_df = pcap_to_df(find_pcap(folder), pcap_label_df, byline=True)
    print(pcap_detail_df)
    pcap_detail_df.to_csv(folder + 'pcap_detail.csv')
    print('[+] File Saved:'+ folder + 'pcap_detail.csv')    
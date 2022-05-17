import pandas as pd
import numpy as np
import time
from scapy.all import *

def ZeekLogs_to_csv(file_path):
    try:
        out_data = pd.read_csv(file_path + '.csv')
        return out_data
    except:
        data_file = open(file_path)
        line = data_file.readline()
        attribs = {}
        while line.strip().startswith('#'):
            # print(line)
            key, *val = line.split()
            attribs[key[1:]] = val
            line = data_file.readline()
        # print(attribs)
        df = {}
        while line.strip().startswith('#close') is False:
            for k, v in zip(attribs['fields'], line.split()):
                # print(k, v)
                if k not in df.keys():
                    df[k] = []
                df[k].append(v)
            line = data_file.readline()

        data_file.close()
        out_data = pd.DataFrame(df)
        out_data.to_csv(file_path + '.csv', index=False)
        return out_data
    
def preprocess_data(file):
    data = ZeekLogs_to_csv(file)
    data['detailed-label'] = data['detailed-label'].replace(to_replace= '-',value= 'Benign')
    data = data.replace(to_replace='-', value=pd.NA)
    data = data.fillna(value=0)
    data['ts'] = data['ts'].astype(np.float64)
    return data

def csv_to_df(csv_file):
    print("[*] Loading:{0}".format(csv_file), end = "\r")
    data = preprocess_data(csv_file)
    df = data[['ts','detailed-label']]
    print("[+] Load Completed:{0}".format(csv_file))
    return df

def pcap_to_df(pcap_file, byline = True):
    print("[*] Loading:{0}".format(pcap_file), end = "\r")    
    if byline == True:
        packets = PcapReader(pcap_file)
        length = "Unknown"
    else:
        packets = rdpcap(pcap_file)
        length = len(packets)
    print("[+] Load Completed:{0}".format(pcap_file))
    df = pd.DataFrame({"ts": []})
    i = 0
    for data in packets:
        print("[*] Prasing Progress:{0}/{1}".format(i,length), end = "\r")
        df.loc[i] = data.time
        i += 1

    print("[+] Prased Items:{0}              ".format(i))
    print("[+] Prase Completed:{0}".format(pcap_file))
    return df.astype(np.float64)

def find_pcap(folder):
    for file in os.listdir(folder):
        if os.path.splitext(file)[1] == '.pcap':
            if str.find(file, '2018') != -1 or str.find(file, '2019') != -1:
                return os.path.join(folder, file)
    
def generate_csv(folder):
    zeek_df = csv_to_df(folder + 'bro/conn.log.labeled')
    print(zeek_df)
    pcap_df = pcap_to_df(find_pcap(folder), byline=True)
    print(pcap_df)
    result = pd.merge(pcap_df, zeek_df, how='left', left_on=['ts'], right_on='ts')
    result = result[['detailed-label']]
    print(result)
    result.to_csv(folder + 'pcap_label.csv')
    print('[+] File Saved:'+ folder + 'pcap_label.csv')

location = '/Volumes/Unicorn/IoTScenarios/'

folder_list = ['CTU-IoT-Malware-Capture-44-1/']

for folder in folder_list:
    start_time = time.time()
    generate_csv(location + folder)
    print("[+] Time Cost {0} Seconds".format(time.time()-start_time))
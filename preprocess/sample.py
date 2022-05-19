import time, json, os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import scipy, os, sys
from sklearn.ensemble import BaggingClassifier
import seaborn as sns
from sklearn.svm import SVC
import joblib
from scapy.all import *
from warnings import filterwarnings

filterwarnings("ignore")
np.set_printoptions(suppress=True)
pd.set_option('display.float_format', lambda x: '%.4f' % x)
pd.set_option('display.max_columns', 50)
pd.set_option('display.max_rows', 50)
plt.style.use({'figure.figsize': (12, 4)})


class CJPCap:

    def __init__(self, CTU='CTU-IoT-Malware-Capture-1-1'):
        self.file_zeek_flow = "%s/bro/conn.log.labeled" % CTU
        self.file_pcap = self.find_pcap("%s/" % CTU)
        self.file_sample = "%s/sample.csv" % CTU

    def find_pcap(self, CTU):
        folder = "%s/" % CTU
        for file in os.listdir(folder):
            if os.path.splitext(file)[1] == '.pcap':
                if str.find(file, '2018') != -1:
                    return os.path.join(folder, file)

    def load_labels(self):
        csv_data = []
        with open(self.file_zeek_flow) as fp:
            data = fp.readline()
            while data:
                if data[0] == '#':
                    if data.find("#fields") == 0:
                        data = data.replace("   ", "\t")
                        data = data.replace("#fields", "").strip("\n")
                        header = ",".join(data.split("\t"))
                        csv_data.append(header[1:])
                else:
                    data = data.replace("   ", "\t")
                    data = ",".join(data.strip("\n").split("\t"))
                    csv_data.append(data)
                data = fp.readline()
        output_file = self.file_zeek_flow.replace("labeled", "csv")
        with open(output_file, "w") as fp:
            for data in csv_data:
                fp.write(data + "\n")
        df = pd.read_csv(output_file)
        df['uuid'] = df['proto'].map(str) + "-" + df['id.orig_h'].map(str) + "-" + df['id.orig_p'].map(str) \
                     + "-" + df['id.resp_h'].map(str) + "-" + df['id.resp_p'].map(str)
        df['duration'].replace("-", '0', inplace=True)
        df['duration'] = df['duration'].astype(float)
        df['sess_start'] = df['ts'] - df['duration']
        df['sess_end'] = df['ts'] + df['duration']
        self.df_zeek_flow = df[['uuid', 'sess_start', 'sess_end', 'label', 'detailed-label', 'duration', 'ts']]
        return df

    def find_label(self, ts, proto, src_h, src_p, dst_h, dst_p):
        proto_str = ""
        if int(proto) == 6:
            proto_str = 'tcp'
        if int(proto) == 17:
            proto_str = 'udp'
        if int(proto) == 1:
            proto_str = 'icmp'
        src_p_str = str(int(src_p))
        dst_p_str = str(int(dst_p))
        uuid = proto_str + "-" + src_h + "-" + src_p_str + "-" + dst_h + "-" + dst_p_str
        np_tmp = self.df_zeek_flow[self.df_zeek_flow['uuid'] == uuid].to_numpy()
        mask = (np_tmp[:, 1] <= ts) & (np_tmp[:, 2] >= ts)
        result = np.where(mask)
        tmp = np_tmp[result]
        if tmp.shape[0] >= 1:
            label = tmp[0, 3]
            detailed_label = tmp[0, 4]
            duration = tmp[0, 5]
            sess_ts = tmp[0, 6]
            return uuid, label, detailed_label, duration, sess_ts
        else:
            return uuid, None, None, None, None

    def parse_cap_file(self, byline=True):
        print("[*] Loading:{0}".format(self.file_pcap), end="\r")
        if byline == True:
            packets = PcapReader(self.file_pcap)
            length = "Unknown"
        else:
            packets = rdpcap(self.file_pcap)
            length = len(packets)
        print("[+] Load Completed:{0}".format(self.file_pcap))
        all_data = []
        i = 0
        for p in packets:
            print("[*] Prasing Progress:{0}/{1}".format(i, length), end="\r")
            tmp = {}
            tmp['ts'] = p.time
            if p.haslayer("IP"):
                for key in p['IP'].fields:
                    tmp["ip_%s" % key] = p['IP'].fields[key]

                if p.haslayer("TCP"):
                    tmp['pcap_id'] = i
                    for key in p['TCP'].fields:
                        tmp["tcp_%s" % key] = p['TCP'].fields[key]
                    uuid, label, detailed_label, duration, sess_ts = self.find_label(tmp['ts'], tmp['ip_proto'],
                                                                                     tmp['ip_src'], tmp['tcp_sport'],
                                                                                     tmp['ip_dst'], tmp['tcp_dport'])
                    if label:
                        tmp['uuid'] = uuid
                        tmp['label'] = label
                        tmp['detailed_label'] = detailed_label
                        tmp['duration'] = duration
                        tmp['sess_ts'] = sess_ts
                        # df = pd.concat([df,pd.DataFrame([tmp])],ignore_index=True)
                        all_data.append(tmp)

                    uuid, label, detailed_label, duration, sess_ts = self.find_label(tmp['ts'], tmp['ip_proto'],
                                                                                     tmp['ip_dst'], tmp['tcp_dport'],
                                                                                     tmp['ip_src'], tmp['tcp_sport'])
                    if label:
                        tmp['uuid'] = uuid
                        tmp['label'] = label
                        tmp['detailed_label'] = detailed_label
                        tmp['duration'] = duration
                        tmp['sess_ts'] = sess_ts
                        # df = pd.concat([df,pd.DataFrame([tmp])],ignore_index=True)
                        all_data.append(tmp)

                if p.haslayer("UDP"):
                    tmp['pcap_id'] = i
                    for key in p['UDP'].fields:
                        tmp["udp_%s" % key] = p['UDP'].fields[key]
                    uuid, label, detailed_label, duration, sess_ts = self.find_label(tmp['ts'], tmp['ip_proto'],
                                                                                     tmp['ip_src'], tmp['udp_sport'],
                                                                                     tmp['ip_dst'], tmp['udp_dport'])
                    if label:
                        tmp['uuid'] = uuid
                        tmp['label'] = label
                        tmp['detailed_label'] = detailed_label
                        tmp['duration'] = duration
                        tmp['sess_ts'] = sess_ts
                        # df = pd.concat([df,pd.DataFrame([tmp])],ignore_index=True)
                        all_data.append(tmp)
                    uuid, label, detailed_label, duration, sess_ts = self.find_label(tmp['ts'], tmp['ip_proto'],
                                                                                     tmp['ip_dst'], tmp['udp_dport'],
                                                                                     tmp['ip_src'], tmp['udp_sport'])
                    if label:
                        tmp['uuid'] = uuid
                        tmp['label'] = label
                        tmp['detailed_label'] = detailed_label
                        tmp['duration'] = duration
                        tmp['sess_ts'] = sess_ts
                        # df = pd.concat([df,pd.DataFrame([tmp])],ignore_index=True)
                        all_data.append(tmp)
            i += 1
            if i > 100 * 10000:
                break
        df = pd.DataFrame(all_data)
        df.to_csv(self.file_sample)
        return df


def main():
    dataset = sys.argv[1].strip()
    test = CJPCap(dataset)
    test.load_labels()
    test.parse_cap_file()


if __name__ == "__main__":
    main()

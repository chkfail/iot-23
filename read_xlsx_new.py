import pandas as pd
# df = pd.read_excel('conn.log.labeled')

def ZeekLogs_csv_to_csv(file_path):
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


def ZeekLogs_excel_to_csv(file_path):
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


ZeekLogs_csv_to_csv('conn 2.log.labeled')

# df.to_csv (r'abc.csv', index = None, header=False)
# print(df)
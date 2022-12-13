from PINBALL.pinball import Pinball
import pandas as pd
import pickle

# TEST_INPUT_FILE = './input-files/2019-07-03-15-15-47-first_start_somfy_gateway.pcap'
# TEST_LABEL_FILE = './input-files/2019-conn.log.labeled.txt'

TEST_INPUT_FILE = './input-files/2018-12-21-15-50-14-192.168.1.195.pcap'
TEST_LABEL_FILE = './input-files/2018-conn.log.labeled.txt'

pinball_instance = Pinball()

# Training phase - use only benign traffic
df = pd.read_csv(TEST_LABEL_FILE, sep='\t')
benign_traffic = df[df['label'].str.contains('Benign', case=False)]

timestamps = df['ts'].tolist()
device_ip = '192.168.1.195' #benign_traffic['id.orig_h'].tolist()[0]

signatures, _s = pinball_instance.extract_event_signatures(TEST_INPUT_FILE, timestamps, device_ip)

print(signatures)

# Store extracted signatures
with open('./signatures-db.pkl', 'wb') as db_file:
    #Save to database pickle file
    pickle.dump(signatures, db_file)

# Retrieve signatures from database
with open('./signatures-db.pkl', 'rb') as db_file:
    signature = pickle.load(db_file)

    validation = pinball_instance.validate_signature(TEST_INPUT_FILE, signature, signature, 0.25, 0.2, 0.15)
    print(validation)

# # 
# def generate_signatures(db, pcap_file):
#     # for timestamp, packet_length, source_ip, dip, _sport, _dport, _l4protocol in PcapReader(pcap_file):
#     #     print(f"{timestamp}\t{packet_length}\t{source_ip}\t{dip}\t{_sport}\t{_dport}\t{_l4protocol}")

#     timestamp, packet_length, source_ip, dip, _sport, _dport, _l4protocol = PcapReader(pcap_file).__next__()
#     print(f"{timestamp}\t{packet_length}\t{source_ip}\t{dip}\t{_sport}\t{_dport}\t{_l4protocol}")

# if __name__ == '__main__':
#     generate_signatures('dbwhatever', './input-files/2019-07-03-15-15-47-first_start_somfy_gateway.pcap')

# # 
# def detect_signatures(db, pcap_file):
#     pass
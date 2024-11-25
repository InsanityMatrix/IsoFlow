import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from ipaddress import ip_address, ip_network
import os
from glob import glob
import re
# Function to classify IP as internal (1) or external (0) or error (2)


# Data Directory to load from
directory = "captures/"
file_paths = glob(os.path.join(directory, "*.json"))

"""
Classify IPs
By: Internal vs External || Server type & External
"""
def classify_ip(ip, internal_network="192.168.0.0/16"):
    try:
        return int(ip_address(ip) in ip_network(internal_network))
    except ValueError:
        return 2
    
"""
Classify Times:
Normal Hours: 0, Night: 1
"""

"""
Protocol: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

1 - ICMP
2 - IGMP
6 -TCP
17 - UDP 
"""

if __name__ == '__main__': # Main Function
    # Read JSON  & Train model <- If Needed
    data = pd.DataFrame()

    for file_path in file_paths:
        print(f"Processing File: {file_path}")
        try:
            fdata = pd.read_json(file_path, lines=True)
            if 'netflow' in fdata.columns:
                fdata = pd.json_normalize(fdata['netflow'])  # Flatten the 'netflow' objects into a DataFrame
            else:
                print("The 'netflow' column is missing in the data.")
                continue

            data = pd.concat([data, fdata], ignore_index=True)
        except Exception as e:
            print(f"Error processing file {file_path}: {e}")

    required_columns = ['protocol', 'l4_src_port', 'l4_dst_port', 'in_bytes', 'in_pkts', 'ipv4_src_addr', 'ipv4_dst_addr']
    missing_columns = [col for col in required_columns if col not in data.columns]
    if missing_columns:
        print(f"Missing required columns: {missing_columns}")
        exit() 
    
    data = data.dropna(subset=required_columns)
    
    # Verify the remaining data
    if data.empty:
        print("No data left after filtering for required columns. Please check your input file.")
        exit()
    # Classify IPs as internal or external
    data['src_internal'] = data['ipv4_src_addr'].apply(classify_ip)
    data['dst_internal'] = data['ipv4_dst_addr'].apply(classify_ip)

    

    #TODO: Prepare Time

    # Prepare Features for Model 
    features = ['protocol', 'l4_src_port', 'l4_dst_port', 'in_bytes', 'in_pkts', 'src_internal', 'dst_internal']
    

    for column in ['protocol', 'l4_src_port', 'l4_dst_port', 'in_bytes', 'in_pkts', 'src_internal', 'dst_internal']:
        non_numeric = data[pd.to_numeric(data[column], errors='coerce').isna()]
        if not non_numeric.empty:
            print(f"Non-numeric values found in column '{column}':")
            print(non_numeric)

    # Standardize the features
    X = data[features]


    X_train, X_test = train_test_split(X, test_size=0.2, random_state=42)
    
    # Standardize the features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Train
    model = IsolationForest(n_estimators=150 , contamination=0.02, random_state=42)
    model.fit(X_train_scaled)

    test_anomalies = model.predict(X_test_scaled)
    X_test['anomaly'] = test_anomalies

    # Save the results with anomalies
    output_file = "isoflow_anomalies.json"
    X_test.to_json(output_file, orient='records', lines=True)
    print(f"Processed data with anomalies saved to {output_file}")

    
    anomalies = X_test[X_test['anomaly'] == -1]
    print(f"Anomalies: {len(anomalies)} out of {len(X_test)}")
    j = 0
    for i, anomaly in anomalies.iterrows():
        print(f"{i}: {anomaly.to_dict()}")
        j += 1
        if j == 10:
            break

    
    # Start Webserver to analyze future Packet Flows
    """
    Webserver - injests logs and adds to data dir, retrain nightly with sliding window to adopt
    to shifting network
    """

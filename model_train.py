import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder, StandardScaler
from ipaddress import ip_address, ip_network
import re
# Function to classify IP as internal (1) or external (0) or error (2)
def classify_ip(ip, internal_network="192.168.0.0/16"):
    try:
        return int(ip_address(ip) in ip_network(internal_network))
    except ValueError:
        return 2

# Load the CSV
file_path = "captures/netflow.csv"  # Update with your CSV file path
data = pd.read_csv(file_path)

# Extract src_ip and src_port
data['src_ip'] = data['src'].str.extract(r'(^[\d\.]+)')
data['src_port'] = data['src'].str.extract(r':(\d+)$').astype(float, errors='ignore').fillna(0)

# Extract dst_ip and dst_port
data['dst_ip'] = data['dst'].str.extract(r'(^[\d\.]+)')
data['dst_port'] = data['dst'].str.extract(r':(\d+)$').astype(float, errors='ignore').fillna(0)

# Convert ports to numeric
data['src_port'] = pd.to_numeric(data['src_port'], errors='coerce').fillna(0)
data['dst_port'] = pd.to_numeric(data['dst_port'], errors='coerce').fillna(0)

# Classify IPs as internal or external
data['src_internal'] = data['src_ip'].apply(classify_ip)
data['dst_internal'] = data['dst_ip'].apply(classify_ip)

# Remove rows where 'src_ip' or 'dst_ip' has a value of 2 (probs IPv6)
data = data[(data['src_internal'] != 2) & (data['dst_internal'] != 2)]

# Enumerate the protocol column
protocol_encoder = LabelEncoder()
data['nproto'] = protocol_encoder.fit_transform(data['proto'])

# Drop original columns that are now split or encoded
#data = data.drop(columns=['src', 'dst', 'src_ip', 'dst_ip'])

# Prepare features for the model
features = ['nproto', 'src_port', 'dst_port', 'in', 'out', 'src_internal', 'dst_internal']
X = data[features]

for column in ['nproto', 'src_port', 'dst_port', 'in', 'out', 'src_internal', 'dst_internal']:
    non_numeric = data[pd.to_numeric(data[column], errors='coerce').isna()]
    if not non_numeric.empty:
        print(f"Non-numeric values found in column '{column}':")
        print(non_numeric)

# Standardize the features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Train an Isolation Forest model
model = IsolationForest(n_estimators=100, contamination=0.02, random_state=42)
model.fit(X_scaled)

# Predict anomalies (1 = normal, -1 = anomaly)
data['anomaly'] = model.predict(X_scaled)

# Save the results with anomalies
output_file = "net_flow_anomalies.csv"
data.to_csv(output_file, index=False)

anomalies = data[data['anomaly'] == -1]
for i, anomaly in anomalies.iterrows():
    print(f"{i}: {anomaly.to_dict()}")

print(f"Processed data with anomalies saved to {output_file}")
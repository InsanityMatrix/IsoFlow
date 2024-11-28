import datetime #TODO: Reorganize and reduce imports
import pandas as pd 
from flask import Flask, request, jsonify
import numpy as np
import requests
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from ipaddress import ip_address, ip_network
import os
import json
from glob import glob
import joblib
import shap
from dotenv import load_dotenv
from filelock import FileLock

load_dotenv()

CONTAMINATION = 0.5 / 100 # To be set as PERCENT_HOSTILE env variable in future

# Flask Webserver
app = Flask(__name__)
model = IsolationForest(n_estimators=150 , contamination=CONTAMINATION, random_state=3)
scaler = StandardScaler()
protocol_columns = None
# Data Directory to load from
DEBUG_MODEL = False
directory = "captures/"
file_paths = glob(os.path.join(directory, "*.json"))
INTERNAL_CIDR = os.getenv('INTERNAL_CIDR')
AEGIS_ADDR = os.getenv('AEGIS_ADDR')


"""
Save Raw Data
Takes JSON data sent to endpoint and appends to todays file,
using a lockfile to ensure threads wait their turn
"""
def save_raw_data(data):
    # Get the current date to name the file
    current_date = datetime.datetime.now().strftime('%Y-%m-%d')
    file_name = f"flows-{current_date}.json"
    lock_file = f"{file_name}.lock"  # Lock file for synchronization

    with FileLock(lock_file): # Ensure only one thread writes at a time
        with open(file_name, 'a') as f:
            f.write(json.dumps(data) + '\n')  # Add newline after each JSON object


"""
Classify IPs
By: Internal vs External
0: External, 1: Internal, 2: Error
"""
def classify_ip(ip, internal_network=INTERNAL_CIDR):
    try:
        return int(ip_address(ip) in ip_network(internal_network))
    except ValueError:
        return 2

def categorize_port(port):
    if 0 <= port <= 1023:
        return 'well_known'
    elif 1024 <= port <= 49151:
        return 'registered'
    elif 49152 <= port <= 65535:
        return 'ephemeral'
    else:
        return 'unknown'

"""
Preprocess Data
Classifies IPs as Internal, External, or Error (IPv6 not supported)
Drops columns of only internal to internal data (Watching for traffic coming in and out)
One Hot Encodes Port categories, and protocols
"""
def preprocess_data(data):
    # Classify IPs as internal or external
    data['src_internal'] = data['ipv4_src_addr'].apply(classify_ip)
    data['dst_internal'] = data['ipv4_dst_addr'].apply(classify_ip)
    # Drop Data where 1 ip isn't external
    data = data.drop(data[(data['src_internal'] == 1) & (data['dst_internal'] == 1)].index)

    data['src_port_category'] = data['l4_src_port'].apply(categorize_port)
    data['dst_port_category'] = data['l4_dst_port'].apply(categorize_port)

    features = ['protocol', 'src_port_category', 'dst_port_category', 'in_bytes', 'in_pkts', 'src_internal', 'dst_internal']
    model_data = data[features]

    #One Hot Encode Protocol Column
    model_data = pd.get_dummies(model_data, columns=['protocol', 'src_port_category', 'dst_port_category']) # In order to help classify certain protcols as anomalous or not

    return model_data

"""
Function: train_model
Reads all json files in datadir, trains isolation forest model and sets scaler

Changes values of model & scaler globals
"""
def train_model():
    original_data = pd.DataFrame()
    
    # Process Data
    for file_path in file_paths:
        print(f"Processing File: {file_path}")
        try:
            fdata = pd.read_json(file_path, lines=True)
            if 'netflow' in fdata.columns:
                fdata = pd.json_normalize(fdata['netflow'])  # Flatten the 'netflow' objects into a DataFrame
            else:
                print("The 'netflow' column is missing in the data.")
                continue

            original_data = pd.concat([original_data, fdata], ignore_index=True)
        except Exception as e:
            print(f"Error processing file {file_path}: {e}")
    
    # Vet for required columns to perform analysis
    required_columns = ['protocol', 'l4_src_port', 'l4_dst_port', 'in_bytes', 'in_pkts', 'ipv4_src_addr', 'ipv4_dst_addr']
    missing_columns = [col for col in required_columns if col not in original_data.columns]
    if missing_columns:
        print(f"Missing required columns: {missing_columns}")
        exit() 
    
    original_data = original_data.dropna(subset=required_columns)
    
    # Verify the remaining data
    if original_data.empty:
        print("No data left after filtering for required columns. Please check your input file.")
        exit()
    
    data = preprocess_data(original_data)
    protocol_columns = data.columns # Keep track for ingestion later
    # Prepare Features for Model 
    
    
    for column in data.columns:
        non_numeric = data[pd.to_numeric(data[column], errors='coerce').isna()]
        if not non_numeric.empty:
            print(f"Non-numeric values found in column '{column}':")
            print(non_numeric)

    # Standardize the features
    features = data.columns.tolist()

    X_train, X_test = train_test_split(data, test_size=0.2, random_state=42)
    
    # Standardize the features
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Train 
    model.fit(X_train_scaled)

    # Save Model
    joblib.dump(model, "model/isolation_forest_model.pkl")
    joblib.dump(scaler, "model/scaler.pkl")
    print("Saved models to models directory")

    test_anomalies = model.predict(X_test_scaled)
    X_test['anomaly'] = test_anomalies
    anomaly_indices = X_test[X_test['anomaly'] == -1].index
    anomalies_data = original_data.loc[anomaly_indices]
    # Save the results with anomalies
    output_file = "isoflow_anomalies.json"
    anomalies_data.to_json(output_file, orient='records', lines=True)
    print(f"Processed anomalies saved to {output_file}")
   
    print(f"Anomalies: {len(anomalies_data)} out of {len(X_test)}")
    if DEBUG_MODEL:
        print("Analyzing Model")
        # Create a SHAP explainer
        explainer = shap.KernelExplainer(model.decision_function, X_train_scaled[:100])  # Use a subset for faster computation
        shap_values = explainer.shap_values(X_train_scaled[:2000])

        # Summary plot for feature importance
        shap.summary_plot(shap_values, X_train[:2000], feature_names=features)

"""
App Webhook
Ingest netflow data from logstash netflow collector
"""
@app.route('/process_flow', methods=['POST'])
def process_flow():
    flow = request.json
    if 'netflow' not in flow:
            return jsonify({"error": "'netflow' key is missing in the payload"}), 400

    # Flatten the netflow data
    flow_df = pd.json_normalize(flow['netflow'])
    if DEBUG_MODEL:
        print(f"Ingested:\n{flow_df}")
    
    # Ensure the required columns exist in the incoming data
    required_columns = ['protocol', 'l4_src_port', 'l4_dst_port', 'in_bytes', 'in_pkts', 'ipv4_src_addr', 'ipv4_dst_addr']
    missing_columns = [col for col in required_columns if col not in flow_df.columns]
    if missing_columns:
        return jsonify({"error": f"Missing required columns: {missing_columns}"}), 400

    save_raw_data(flow)
    
    # Preprocess Data
    mdata = preprocess_data(flow_df)
    if mdata.empty:
        # Was internal traffic
        return jsonify({"Report": f"Internal Traffic"}), 200
    mdata = mdata.reindex(columns=protocol_columns, fill_value=0)
    X = mdata
    print(f"{X}")
    # Standardize the features
    X_scaled = scaler.transform(X) # Scaler is same scaler as used in the model

    # Predict anomaly
    flow_df['anomaly'] = model.predict(X_scaled)
    
    anomalies = flow_df[flow_df['anomaly'] == -1]
    if not anomalies.empty:
        # Prepare anomaly data for sending to the external web server
        anomaly_payload = anomalies.to_dict(orient='records')

        try:
            response = requests.post(f"http://{AEGIS_ADDR}/anomaly", json=anomaly_payload)
            if response.status_code == 200:
                print(f"Successfully sent {len(anomalies)} anomalies to the web server.")
            else:
                print(f"Failed to send anomalies. HTTP {response.status_code}: {response.text}")
        except Exception as e:
            print(f"Error sending anomalies to the web server: {e}")


    # Return the prediction result
    result = flow_df[['anomaly']].iloc[0].to_dict()  # Return only the anomaly status of the first row
    return jsonify(result)

"""
    Model Initialization & Webserver
    Webserver - injests logs and adds to data dir, retrain nightly with sliding window to adopt
    to shifting network
    """
if __name__ == '__main__': # Main Function
    # If pkl file exists, load model & scaler
    normal_conditions = os.path.isfile("model/isolation_forest_model.pkl") and os.path.isfile("model/scaler.pkl")
    no_train = normal_conditions and not DEBUG_MODEL
    if no_train:
        print("Loading model from pretrained.")
        model = joblib.load("model/isolation_forest_model.pkl")
        scaler = joblib.load("model/scaler.pkl")
    else: # else train model
        train_model()
   
    
    # Start Webserver to analyze future Packet Flows
    app.run(debug=True, port=5300, host='0.0.0.0')
    

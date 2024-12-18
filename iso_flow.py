import datetime #TODO: Reorganize and reduce imports
from matplotlib import pyplot as plt
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
import threading

load_dotenv()

PERCENT_HOSTILE = os.getenv('PERCENT_HOSTILE') or 0.5
CONTAMINATION = float(PERCENT_HOSTILE) / 100 
# Flask Webserver
app = Flask(__name__)
model = IsolationForest(n_estimators=150 , contamination=CONTAMINATION, random_state=3)
scaler = StandardScaler()
models = {}
scalers = {}
protocol_columns = None
# Data Directory to load from
DEBUG_MODEL = False
DATA_DIR = "data/"
directory = "captures/"
file_paths = glob(os.path.join(directory, "*.json"))
INTERNAL_CIDR = os.getenv('INTERNAL_CIDR')
AEGIS_ADDR = os.getenv('AEGIS_ADDR')

lock = threading.Lock()

"""
Save Raw Data
Takes JSON data sent to endpoint and appends to todays file,
using a lockfile to ensure threads wait their turn
"""
def save_raw_data(data):
    # Get the current date to name the file
    current_date = datetime.datetime.now().strftime('%Y-%m-%d')
    file_name = f"{directory}/flows-{current_date}.json"
    
    with lock: # Ensure only one thread writes at a time
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
Preprocess Data
Classifies IPs as Internal, External, or Error (IPv6 not supported)
Drops columns of only internal to internal data (Watching for traffic coming in and out)
One Hot Encodes Port categories, and protocols
"""
def preprocess_data_nodrop(data):
    # Classify IPs as internal or external
    data['src_internal'] = data['ipv4_src_addr'].apply(classify_ip)
    data['dst_internal'] = data['ipv4_dst_addr'].apply(classify_ip)
    # Drop Data where 1 ip isn't external
    data = data.drop(data[(data['src_internal'] == 1) & (data['dst_internal'] == 1)].index)

    data['src_port_category'] = data['l4_src_port'].apply(categorize_port)
    data['dst_port_category'] = data['l4_dst_port'].apply(categorize_port)

    
    features = ['protocol', 'src_port_category', 'dst_port_category', 'in_bytes', 'in_pkts', 'src_internal', 'dst_internal']
    return data, features

"""
Function: train_model
Reads all json files in datadir, trains isolation forest model and sets scaler

Changes values of model & scaler globals
"""
def train_model():
    global protocol_columns
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
    
    fdata, features = preprocess_data_nodrop(original_data) # Just to make sure we train with all of the columns
    protocol_columns = preprocess_data(original_data).columns # Keep track for ingestion later #TODO: make this more efficient
    
    joblib.dump(protocol_columns, 'model/columns.pkl')
    # Make a model per IP (What's an anomaly for one machine may be normal for another) TODO: Bears the consequence of new DHCP ips failing to be evaluated
    src_vals = [x for x in fdata['ipv4_src_addr'].unique() if classify_ip(x) == 1]
    dst_vals = [x for x in fdata['ipv4_dst_addr'].unique() if classify_ip(x) == 1]

    ips = set(src_vals)
    for ip in dst_vals:
        ips.add(ip)
    
    explanations = []
    for ip in ips: # TODO: Multithread
        data = fdata.loc[
            (fdata['ipv4_src_addr'] == ip) | (fdata['ipv4_dst_addr'] == ip)
        ]
        data = data[features]
        data = pd.get_dummies(data, columns=['protocol', 'src_port_category', 'dst_port_category'])
        data = data.reindex(columns=protocol_columns, fill_value=0)
        # Prepare Features for Model 
        for column in data.columns:
            non_numeric = data[pd.to_numeric(data[column], errors='coerce').isna()]
            if not non_numeric.empty:
                print(f"Non-numeric values found in column '{column}':")
                print(non_numeric)

        X_train, X_test = train_test_split(data, test_size=0.2, random_state=42)
        
        scalers[ip] = StandardScaler()
        # Standardize the features
        X_train_scaled = scalers[ip].fit_transform(X_train)
        X_test_scaled = scalers[ip].transform(X_test)

        models[ip] = IsolationForest(n_estimators=150 , contamination=CONTAMINATION, random_state=3)
        models[ip].fit(X_train_scaled)
        #Save model
        joblib.dump(models[ip], f"model/model.{ip}.pkl")
        joblib.dump(scalers[ip], f"model/scaler.{ip}.pkl")
        print(f"Saved model {ip} to models directory")
    

        test_anomalies = models[ip].predict(X_test_scaled)
        X_test['anomaly'] = test_anomalies
        anomaly_indices = X_test[X_test['anomaly'] == -1].index
        anomalies_data = original_data.loc[anomaly_indices]
        # Save the results with anomalies
        output_file = f"{DATA_DIR}{ip}_anomalies.json"
        anomalies_data.to_json(output_file, orient='records', lines=True)
        print(f"Processed anomalies saved to {output_file}")
   
        print(f"Anomalies for {ip}: {len(anomalies_data)} out of {len(X_test)}")
        if len(anomalies_data) == 0:
            continue
        nfeatures = data.columns.tolist()
        if DEBUG_MODEL and len(anomalies_data) >= 2:
            print("Analyzing Model")
            # Create a SHAP explainer
            exp = len(X_train_scaled) if len(X_train_scaled) < 100 else 100
            val =  len(X_train_scaled) if len(X_train_scaled) < 2000 else 2000

            explainer = shap.KernelExplainer(models[ip].decision_function, X_train_scaled[:exp])  # Use a subset for faster computation
            shap_values = explainer.shap_values(X_train_scaled[:val])
            
            # Summary plot for feature importance
            explanations.append((shap_values, X_train[:val], nfeatures, ip))
            #shap.summary_plot(shap_values, X_train[:val], feature_names=nfeatures)
    
    for explanation in explanations:
        shap_values, xval, nfeatures, ip = explanation # unpack tuple
        shap.summary_plot(shap_values, xval, feature_names=nfeatures, show=False)
        plt.title(f"{ip} Anomaly Decision Function")
        plt.show()
        

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
        print("Internal Traffic")
        return jsonify({"Report": f"Internal Traffic"}), 200
    
    intip = flow['netflow']['ipv4_src_addr'] if classify_ip(flow['netflow']['ipv4_src_addr']) == 1 else flow['netflow']['ipv4_dst_addr'] # Retrieve internal IP to run model on
    mdata = mdata.reindex(columns=protocol_columns, fill_value=0)
    X = mdata
    # Standardize the features
    try:
        X_scaled = scalers[intip].transform(X) # Scaler is same scaler as used in the model

        # Predict anomaly
        flow_df['anomaly'] = models[intip].predict(X_scaled)
        
        anomalies = flow_df[flow_df['anomaly'] == -1]
        if not anomalies.empty:
            # Prepare anomaly data for sending to the external web server
            anomaly_payload = anomalies.to_dict(orient='records')
            print(f"Anomaly: {anomaly_payload}")
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
        print(f"EXTERNAL {flow_df[['protocol','ipv4_src_addr','in_bytes','anomaly']]}")
        return jsonify(result), 200
    except KeyError as ke:
        return jsonify({"error": "Encountered a KeyError, internal ip is currently not recognized."}), 400
"""
    Model Initialization & Webserver
    Webserver - injests logs and adds to data dir, retrain nightly with sliding window to adopt
    to shifting network
    """
if __name__ == '__main__': # Main Function
    # If pkl file exists, load model & scaler
    normal_conditions = os.path.isfile("model/columns.pkl")
    no_train = normal_conditions and not DEBUG_MODEL
    if no_train: # Until I fix not saving training columns
        print("Loading model from pretrained.")
        
        protocol_columns = joblib.load('model/columns.pkl')
        model_files = glob(os.path.join("model", "*.pkl"))
        for mod in model_files:
            if mod.startswith("model/model."):
                pos = mod.index("model/model.") + len("model/model.")
                ip = mod[pos:].replace(".pkl", "")
                models[ip] = joblib.load(f"model/model.{ip}.pkl")
                scalers[ip] = joblib.load(f"model/scaler.{ip}.pkl")
    else: # else train model
        train_model()
   
    
    # Start Webserver to analyze future Packet Flows
    app.run(debug=True, port=5300, host='0.0.0.0')

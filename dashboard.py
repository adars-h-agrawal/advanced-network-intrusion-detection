import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler
import warnings
import os
import pickle
warnings.filterwarnings('ignore')

# Set UTF-8 encoding for matplotlib
plt.rcParams['font.sans-serif'] = ['Arial']
plt.rcParams['axes.unicode_minus'] = False

# Page Config
st.set_page_config(page_title="NIDS Dashboard", layout="wide", page_icon="🛡️")

# Custom CSS
st.markdown("""
    <style>
    .stAlert { padding: 10px; }
    .metric-green { color: #00ff00; }
    .metric-red { color: #ff4444; }
    </style>
""", unsafe_allow_html=True)

st.title("🛡️ Network Intrusion Detection System Dashboard")
st.markdown("**Training on Historical Data | Testing on Real-time Captures**")
st.markdown("---")

# File paths
HISTORICAL_DATA_FILE = "data/historical_data.csv"
SESSION_DATA_FILE = "data/captured_data.csv"
MODEL_FILE = "models/trained_model.pkl"
SCALER_FILE = "models/scaler.pkl"

# Sidebar
with st.sidebar:
    st.header("⚙️ Model Settings")
    
    model_type = st.selectbox(
        "ML Algorithm", 
        ["Random Forest", "Decision Tree", "Logistic Regression"],
        help="Choose the machine learning algorithm"
    )
    
    st.markdown("---")
    st.subheader("🎯 Model Parameters")
    
    if model_type == "Random Forest":
        n_estimators = st.slider("Number of Trees", 50, 200, 100, 10)
        max_depth = st.slider("Max Depth", 5, 20, 10, 1)
    elif model_type == "Decision Tree":
        max_depth = st.slider("Max Depth", 3, 15, 8, 1)
    
    st.markdown("---")
    st.subheader("🗂️ Data Management")
    
    if st.button("🗑️ Clear Historical Data"):
        if os.path.exists(HISTORICAL_DATA_FILE):
            os.remove(HISTORICAL_DATA_FILE)
            st.success("Historical data cleared!")
            st.rerun()
    
    if st.button("🗑️ Clear Saved Model"):
        if os.path.exists(MODEL_FILE):
            os.remove(MODEL_FILE)
            os.remove(SCALER_FILE)
            st.success("Model cleared!")
            st.rerun()

# Load Historical Training Data
@st.cache_data
def load_training_data():
    """Load historical data for training"""
    if os.path.exists(HISTORICAL_DATA_FILE):
        try:
            df = pd.read_csv(HISTORICAL_DATA_FILE)
            return df
        except Exception as e:
            st.error(f"Error loading historical data: {e}")
            return None
    return None

# Load Test Data (Current Session)
@st.cache_data
def load_test_data():
    """Load current session data for testing"""
    if os.path.exists(SESSION_DATA_FILE):
        try:
            df = pd.read_csv(SESSION_DATA_FILE)
            return df
        except Exception as e:
            st.error(f"Error loading test data: {e}")
            return None
    return None

# Load data
train_df = load_training_data()
test_df = load_test_data()

# Check data availability
col1, col2 = st.columns(2)

with col1:
    if train_df is not None:
        st.success(f"✅ Training Data: {len(train_df)} packets (Historical)")
    else:
        st.error("❌ No training data found!")
        st.info("Run 'nids.py' multiple times to build historical dataset")

with col2:
    if test_df is not None:
        st.info(f"📊 Test Data: {len(test_df)} packets (Current Session)")
    else:
        st.warning("⚠️ No test data found!")
        st.info("Run 'nids.py' to capture test packets")

if train_df is None:
    st.stop()

# Dataset Overview
st.markdown("---")
st.header("📊 Dataset Overview")

col1, col2, col3, col4 = st.columns(4)

train_normal = len(train_df[train_df['Status'] == 'Normal'])
train_suspicious = len(train_df[train_df['Status'].isin(['Suspicious', 'Attack'])])

col1.metric("Training Samples", len(train_df))
col2.metric("Normal Traffic", train_normal, delta=f"{train_normal/len(train_df)*100:.1f}%")
col3.metric("Suspicious Traffic", train_suspicious, delta=f"{train_suspicious/len(train_df)*100:.1f}%")

if test_df is not None:
    col4.metric("Test Samples", len(test_df))
else:
    col4.metric("Test Samples", "0", delta="No data")

# Check class balance
if train_suspicious < 10:
    st.warning("⚠️ Very few suspicious packets in training data. The model may not detect attacks well.")
    st.info("💡 Try to generate more suspicious traffic (port scans, large packets, etc.)")

# Visualizations
st.markdown("---")
st.header("📈 Training Data Analysis")

col1, col2 = st.columns(2)

with col1:
    st.subheader("Training Set Distribution")
    fig, ax = plt.subplots(figsize=(6, 4))
    # Force correct order for colors
    status_order = ['Normal', 'Suspicious']
    train_counts = train_df['Status'].value_counts().reindex(status_order)
    colors = ['#90ee90', '#ff9999']  # Normal green, Suspicious red
    train_counts.plot(kind='pie', autopct='%1.1f%%', colors=colors, ax=ax, startangle=90)
    ax.set_ylabel('')
    st.pyplot(fig)

with col2:
    st.subheader("Anomaly Score Distribution")
    fig, ax = plt.subplots(figsize=(6, 4))
    train_df['Anomaly_Score'].hist(bins=30, ax=ax, color='skyblue', edgecolor='black')
    ax.set_xlabel('Anomaly Score')
    ax.set_ylabel('Frequency')
    ax.axvline(0.5, color='red', linestyle='--', label='Threshold (0.5)')
    ax.legend()
    st.pyplot(fig)

# Feature Analysis
col1, col2 = st.columns(2)

with col1:
    st.subheader("Packet Length Distribution")
    fig, ax = plt.subplots(figsize=(6, 4))
    train_df[train_df['Status'] == 'Normal']['Length'].hist(bins=30, alpha=0.6, label='Normal', color='green', ax=ax)
    train_df[train_df['Status'].isin(['Suspicious', 'Attack'])]['Length'].hist(bins=30, alpha=0.6, label='Suspicious', color='red', ax=ax)
    ax.set_xlabel('Packet Length')
    ax.set_ylabel('Frequency')
    ax.legend()
    st.pyplot(fig)

with col2:
    st.subheader("Top Destination Ports")
    top_ports = train_df['Destination_Port'].dropna().value_counts().head(10)
    if not top_ports.empty:
        fig, ax = plt.subplots(figsize=(6, 4))
        top_ports.plot(kind='barh', ax=ax, color='steelblue')
        ax.set_xlabel('Packet Count')
        st.pyplot(fig)

# Machine Learning Section
st.markdown("---")
st.header("🤖 Machine Learning Model Training")

# Prepare features
feature_cols = ['Length', 'Anomaly_Score', 'TTL', 'Payload_Size']
available_features = [col for col in feature_cols if col in train_df.columns]

# st.info(f"📊 Using features: {', '.join(available_features)}")

# Handle missing values
train_df_ml = train_df.copy()
for col in available_features:
    train_df_ml[col] = train_df_ml[col].fillna(train_df_ml[col].median())

# Create labels (1 = Attack, 0 = Normal)
train_df_ml['Label'] = np.where(train_df_ml['Status'].isin(['Suspicious', 'Attack']), 1, 0)

X_train = train_df_ml[available_features]
y_train = train_df_ml['Label']

# Check if we have both classes
if len(np.unique(y_train)) < 2:
    st.error("❌ Training data has only one class! Need both normal and suspicious packets.")
    st.stop()

# Scale features
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)

# Train model
st.subheader("🎯 Training Model...")

with st.spinner("Training in progress..."):
    if model_type == "Random Forest":
        model = RandomForestClassifier(n_estimators=n_estimators, max_depth=max_depth, random_state=42)
    elif model_type == "Decision Tree":
        from sklearn.tree import DecisionTreeClassifier
        model = DecisionTreeClassifier(max_depth=max_depth, random_state=42)
    else:
        from sklearn.linear_model import LogisticRegression
        model = LogisticRegression(random_state=42, max_iter=1000)
    
    model.fit(X_train_scaled, y_train)
    
    # Save model
    with open(MODEL_FILE, 'wb') as f:
        pickle.dump(model, f)
    with open(SCALER_FILE, 'wb') as f:
        pickle.dump(scaler, f)

st.success("✅ Model trained and saved successfully!")

# Training accuracy (on training set - for reference only)
train_predictions = model.predict(X_train_scaled)
train_accuracy = accuracy_score(y_train, train_predictions)

col1, col2, col3 = st.columns(3)
col1.metric("Model Type", model_type)
col2.metric("Training Accuracy", f"{train_accuracy*100:.2f}%")
col3.metric("Training Samples", len(X_train))

# Feature Importance
if hasattr(model, 'feature_importances_'):
    st.subheader("🎯 Feature Importance")
    importance_df = pd.DataFrame({
        'Feature': available_features,
        'Importance': model.feature_importances_
    }).sort_values('Importance', ascending=False)
    
    fig, ax = plt.subplots(figsize=(8, 4))
    importance_df.plot(kind='barh', x='Feature', y='Importance', ax=ax, color='steelblue', legend=False)
    ax.set_xlabel('Importance Score')
    st.pyplot(fig)
    
    st.dataframe(importance_df, width='stretch')

# Test Set Evaluation
if test_df is not None and len(test_df) > 0:
    st.markdown("---")
    st.header("🧪 Model Testing on Real-time Captures")
    
    # Prepare test data
    test_df_ml = test_df.copy()
    for col in available_features:
        if col in test_df_ml.columns:
            test_df_ml[col] = test_df_ml[col].fillna(test_df_ml[col].median())
    
    # Check if test data has the required features
    missing_features = [f for f in available_features if f not in test_df_ml.columns]
    if missing_features:
        st.warning(f"⚠️ Test data missing features: {missing_features}")
    else:
        test_df_ml['Label'] = np.where(test_df_ml['Status'].isin(['Suspicious', 'Attack']), 1, 0)
        
        X_test = test_df_ml[available_features]
        y_test = test_df_ml['Label']
        
        # Check if test data has only one class
        unique_test_labels = np.unique(y_test)
        
        # Scale test data
        X_test_scaled = scaler.transform(X_test)
        
        # Predict
        y_pred = model.predict(X_test_scaled)
        y_pred_proba = model.predict_proba(X_test_scaled)
        
        # Calculate metrics
        test_accuracy = accuracy_score(y_test, y_pred)
        
        # Add predictions to dataframe
        test_df_ml['ML_Prediction'] = ['Suspicious' if p == 1 else 'Normal' for p in y_pred]
        test_df_ml['Confidence'] = [y_pred_proba[i][y_pred[i]] for i in range(len(y_pred))]
        
        # Display results
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Test Accuracy", f"{test_accuracy*100:.2f}%")
        
        test_normal = np.sum(y_pred == 0)
        test_attacks = np.sum(y_pred == 1)
        col2.metric("Predicted Normal", test_normal)
        col3.metric("Predicted Suspicious", test_attacks)
        col4.metric("Average Confidence", f"{y_pred_proba.max(axis=1).mean():.3f}")
        
        # Confusion Matrix
        st.subheader("📊 Confusion Matrix")
        col1, col2 = st.columns(2)
        
        with col1:
            cm = confusion_matrix(y_test, y_pred)
            fig, ax = plt.subplots(figsize=(6, 5))
            sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=ax,
                       xticklabels=['Normal', 'Suspicious'], yticklabels=['Normal', 'Suspicious'])
            ax.set_ylabel('True Label')
            ax.set_xlabel('Predicted Label')
            ax.set_title('Test Set Confusion Matrix')
            st.pyplot(fig)
        
        with col2:
            st.write("**Classification Report**")
            
            # Handle single class case
            if len(unique_test_labels) == 1:
                st.warning(f"⚠️ Test data contains only one class: {'Suspicious' if unique_test_labels[0] == 1 else 'Normal'}")
                st.info("💡 Capture more diverse traffic to evaluate both classes")
                
                # Show simple metrics
                single_class_name = 'Suspicious' if unique_test_labels[0] == 1 else 'Normal'
                metrics_data = {
                    'Metric': ['Accuracy', 'Samples'],
                    'Value': [f"{test_accuracy*100:.2f}%", len(y_test)]
                }
                metrics_df = pd.DataFrame(metrics_data)
                st.dataframe(metrics_df, width='stretch')
            else:
                # Full classification report
                report = classification_report(y_test, y_pred, 
                                             target_names=['Normal', 'Suspicious'], 
                                             output_dict=True, 
                                             zero_division=0,
                                             labels=[0, 1])
                report_df = pd.DataFrame(report).transpose()
                st.dataframe(report_df.style.format("{:.3f}"), height=250)
        
        # Show test results
        st.subheader("🔍 Test Set Predictions")
        
        # Add result comparison
        test_display = test_df_ml[['Timestamp', 'Source_IP', 'Destination_IP', 'Destination_Port', 
                                   'Length', 'Status', 'ML_Prediction', 'Confidence']].copy()
        
        # Highlight mismatches
        def highlight_predictions(row):
            if row['Status'] in ['Suspicious', 'Attack'] and row['ML_Prediction'] == 'Attack':
                return ['background-color: #90EE90'] * len(row)  # Light green - correct attack detection
            elif row['Status'] == 'Normal' and row['ML_Prediction'] == 'Normal':
                return ['background-color: #00BFFF'] * len(row)  # Light blue - correct normal
            elif row['ML_Prediction'] == 'Attack':
                return ['background-color: #FFB6C1'] * len(row)  # Light red - false positive
            else:
                return ['background-color: #FFA500'] * len(row)  # Light orange - false negative
        
        st.dataframe(
            test_display.style.apply(highlight_predictions, axis=1),
            width='stretch',
            height=400
        )
        
        st.caption("🟢 Green: Correct attack detection | 🔵 Blue: Correct normal | 🔴 Pink: False positive | 🟠 Orange: False negative")
        
        # Show detected attacks
        detected_attacks = test_df_ml[test_df_ml['ML_Prediction'] == 'Attack']
        if len(detected_attacks) > 0:
            st.subheader("🚨 Detected Attacks in Test Set")
            st.dataframe(
                detected_attacks[['Timestamp', 'Source_IP', 'Destination_IP', 
                                'Destination_Port', 'Length', 'Confidence', 'Reason']],
                width='stretch'
            )

# Interactive Prediction
st.markdown("---")
st.header("🔮 Interactive Packet Prediction")
st.markdown("Enter packet characteristics to test the trained model:")

col1, col2, col3, col4 = st.columns(4)
length_input = col1.number_input("Packet Length", 1, 5000, 500)
score_input = col2.number_input("Anomaly Score", 0.0, 1.0, 0.3, 0.1)
ttl_input = col3.number_input("TTL", 1, 255, 64)
payload_input = col4.number_input("Payload Size", 0, 5000, 200)

if st.button("🔮 Predict Packet Status", type="primary"):
    user_data = pd.DataFrame([[length_input, score_input, ttl_input, payload_input]], 
                             columns=available_features)
    user_scaled = scaler.transform(user_data)
    user_pred = model.predict(user_scaled)[0]
    user_proba = model.predict_proba(user_scaled)[0]
    
    col1, col2 = st.columns(2)
    with col1:
        if user_pred == 1:
            st.error(f"🚨 **ATTACK DETECTED**")
        else:
            st.success(f"✅ **Normal Traffic**")
    
    with col2:
        st.metric("Confidence", f"{user_proba[user_pred]*100:.1f}%")
    
    st.write("**Prediction Probabilities:**")
    prob_df = pd.DataFrame({
        'Class': ['Normal', 'Attack'],
        'Probability': [f"{user_proba[0]*100:.2f}%", f"{user_proba[1]*100:.2f}%"]
    })
    st.dataframe(prob_df, width='stretch')


# ==================================================================================================
# 🧠 LIVE CAPTURE SECTION (ADDED)
# ==================================================================================================
import threading
import time
from scapy.all import sniff, IP, TCP, UDP

st.markdown("---")
st.header("🧠 Live Network Monitoring (Real-Time Prediction)")

st.markdown("""Capture live packets from your network and classify them using the trained ML model.""")

# Ensure model + scaler exist
if not os.path.exists(MODEL_FILE) or not os.path.exists(SCALER_FILE):
    st.warning("⚠️ Train and save a model first before starting live monitoring.")
else:
    # Load trained model + scaler
    with open(MODEL_FILE, "rb") as f:
        live_model = pickle.load(f)
    with open(SCALER_FILE, "rb") as f:
        live_scaler = pickle.load(f)

    # Capture settings
    packet_count = st.number_input("Packets to Capture", 10, 300, 30, 10)
    iface = st.text_input("Network Interface (e.g. en0, wlan0) — leave blank for auto-detect", "")
    start_live = st.button("🚀 Start Live Monitoring")

    def extract_features(packet):
        """Extract relevant features for ML prediction"""
        features = {"Length": len(packet), "TTL": None, "Payload_Size": 0}
        if packet.haslayer(IP):
            features["TTL"] = packet[IP].ttl
            if packet.haslayer(TCP):
                features["Payload_Size"] = len(packet[TCP].payload)
            elif packet.haslayer(UDP):
                features["Payload_Size"] = len(packet[UDP].payload)
        # simple anomaly indicator
        score = 0.0
        if features["Length"] > 800: score += 0.3
        if features["TTL"] and (features["TTL"] < 30 or features["TTL"] > 128): score += 0.2
        features["Anomaly_Score"] = score
        return features

    if start_live:
        st.info("⏳ Capturing live packets... please wait.")
        placeholder_table = st.empty()
        placeholder_status = st.empty()
        captured_data = []

        def process_packet(packet):
            feats = extract_features(packet)
            X = pd.DataFrame([[feats["Length"], feats["Anomaly_Score"], feats["TTL"] or 64, feats["Payload_Size"]]],
                             columns=["Length", "Anomaly_Score", "TTL", "Payload_Size"])
            X_scaled = live_scaler.transform(X)
            pred = live_model.predict(X_scaled)[0]
            proba = live_model.predict_proba(X_scaled)[0]
            conf = round(proba[pred], 3)
            label = "Attack" if pred == 1 else "Normal"
            entry = {
                "Timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "Length": feats["Length"],
                "TTL": feats["TTL"],
                "Payload_Size": feats["Payload_Size"],
                "Anomaly_Score": feats["Anomaly_Score"],
                "Prediction": label,
                "Confidence": conf
            }
            captured_data.append(entry)
            print(entry)
            return entry

        def capture():
            sniff(count=packet_count, prn=process_packet, iface=iface or None, timeout=60)

        # Run capture in separate thread (so Streamlit stays responsive)
        thread = threading.Thread(target=capture)
        thread.start()

        # Live updating table
        while thread.is_alive():
            if captured_data:
                df_live = pd.DataFrame(captured_data)
                placeholder_table.dataframe(df_live.tail(10), use_container_width=True)
                attacks = (df_live["Prediction"] == "Attack").sum()
                placeholder_status.info(f"📡 Captured: {len(df_live)} | 🚨 Attacks: {attacks}")
            time.sleep(2)

        st.success(f"✅ Capture complete! {len(captured_data)} packets processed.")
        df_final = pd.DataFrame(captured_data)
        st.dataframe(df_final.tail(20), use_container_width=True)
        df_final.to_csv("data/live_predictions.csv", index=False)
        st.info("📁 Results saved to `data/live_predictions.csv`")


# ==================================================================================================
# 📊 LIVE CAPTURE INSIGHTS SECTION
# ==================================================================================================
st.markdown("---")
st.header("📊 Live Capture Insights")

if os.path.exists("data/live_predictions.csv"):
    try:
        live_df = pd.read_csv("data/live_predictions.csv")

        if len(live_df) > 0:
            st.success(f"✅ Loaded {len(live_df)} captured packets for insights.")

            # Overall Metrics
            total_packets = len(live_df)
            total_attacks = (live_df["Prediction"] == "Attack").sum()
            total_normal = (live_df["Prediction"] == "Normal").sum()
            avg_confidence = live_df["Confidence"].mean()

            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Total Packets", total_packets)
            col2.metric("Predicted Normal", total_normal)
            col3.metric("Predicted Attacks", total_attacks)
            col4.metric("Average Confidence", f"{avg_confidence:.2f}")

            # 1️⃣ & 2️⃣ Prediction and Confidence Distributions
            st.subheader("📊 Prediction & Confidence Distributions")
            col1, col2 = st.columns(2)
            with col1:
                fig, ax = plt.subplots(figsize=(5, 4))
                sns.countplot(x="Prediction", data=live_df, palette=["#90ee90", "#ff9999"], ax=ax)
                ax.set_title("Normal vs Attack Predictions")
                st.pyplot(fig)
            with col2:
                fig, ax = plt.subplots(figsize=(5, 4))
                # Only enable KDE if confidence has variance
                kde_flag = live_df["Confidence"].nunique() > 1
                sns.histplot(
                    live_df, x="Confidence", hue="Prediction", kde=kde_flag,
                    bins=20, palette={"Normal": "green", "Attack": "red"}, ax=ax
                )
                ax.set_title("Confidence Levels by Prediction")
                st.pyplot(fig)

            # 3️⃣ Packet Length & Anomaly Analysis
            st.subheader("📦 Feature Distribution (Length & Anomaly Score)")
            col1, col2 = st.columns(2)
            with col1:
                fig, ax = plt.subplots(figsize=(5, 4))
                sns.histplot(live_df, x="Length", hue="Prediction", bins=30, kde=True,
                             palette={"Normal": "green", "Attack": "red"}, ax=ax)
                ax.set_title("Packet Length Distribution")
                st.pyplot(fig)
            with col2:
                fig, ax = plt.subplots(figsize=(5, 4))
                sns.histplot(live_df, x="Anomaly_Score", hue="Prediction", bins=20, kde=(live_df["Confidence"].nunique() > 1),
                             palette={"Normal": "green", "Attack": "red"}, ax=ax)
                ax.set_title("Anomaly Score Distribution")
                st.pyplot(fig)

            # 4️⃣ Time Series View
            st.subheader("🕒 Attack Timeline")
            try:
                live_df["Timestamp"] = pd.to_datetime(live_df["Timestamp"])
                timeline = live_df.groupby(
                    [pd.Grouper(key="Timestamp", freq="5S"), "Prediction"]
                ).size().unstack(fill_value=0)

                fig, ax = plt.subplots(figsize=(8, 4))
                timeline.plot(ax=ax, marker="o")
                ax.set_ylabel("Packet Count")
                ax.set_title("Attack Frequency Over Time (5-sec intervals)")
                st.pyplot(fig)
            except Exception as e:
                st.warning(f"Could not create time-based plot: {e}")

            # 5️⃣ Recent Attack Table
            st.subheader("🚨 Recent Detected Attacks")
            recent_attacks = live_df[live_df["Prediction"] == "Attack"].sort_values(
                by="Timestamp", ascending=False
            )
            if len(recent_attacks) > 0:
                st.dataframe(
                    recent_attacks[["Timestamp", "Length", "TTL", "Payload_Size", "Anomaly_Score", "Confidence"]],
                    use_container_width=True,
                    height=300,
                )
            else:
                st.info("✅ No attacks detected in live capture.")

        else:
            st.warning("⚠️ No packets found in `live_predictions.csv`.")
    except Exception as e:
        st.error(f"Error loading live capture insights: {e}")
else:
    st.info("ℹ️ Run a live capture session first to see insights here.")


# Footer
st.markdown("---")
st.caption("🛡️ Network Intrusion Detection System | Train on Historical Data, Test on Real-time Captures")

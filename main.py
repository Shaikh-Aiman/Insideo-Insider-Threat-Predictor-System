import threading
import traceback
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import pandas as pd
import numpy as np
import random
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import webbrowser
import matplotlib
matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
from PIL import Image, ImageTk
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout
from tensorflow.keras.optimizers import Adam
import sys
import os
import tempfile
import shutil

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS 
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

IMG_1 = resource_path("assets/BASIC_INFO.jpg")
IMG_2 = resource_path("assets/PROJECT_FLOW.png")
IMG_3 = resource_path("assets/About_ME.jpg")

try:
    import networkx as nx
    HAS_NETWORKX = True
except Exception:
    HAS_NETWORKX = False

HAS_TF = True

DEFAULT_RISK_THRESHOLD = 20
PLOT_DPI = 100

MITRE_EVENT_MAP = {
    "login_fail": ("Credential Access", "Brute Force (T1110)"),
    "failed_login": ("Credential Access", "Brute Force (T1110)"),
    "login_success": ("Credential Access", "Valid Accounts (T1078)"),
    "login_from_unusual_ip": ("Credential Access", "Valid Accounts (T1078)"),

    "file_read": ("Collection", "Data from Local System (T1005)"),
    "read_file": ("Collection", "Data from Local System (T1005)"),

    "file_write": ("Impact", "Data Manipulation"),
    "file_delete": ("Impact", "Data Destruction (T1485)"),

    "file_download": ("Exfiltration", "Exfiltration Over Network (T1041)"),
    "data_copy_to_usb": ("Exfiltration", "Exfiltration to Removable Media"),

    "system_config_change": ("Defense Evasion", "Modify System Configuration")
}

def load_csv(path):
    try:
        df = pd.read_csv(path)
    except Exception:
        df = pd.read_csv(path, sep=";")
    time_cols = [
        "timestamp", "time", "date", "datetime",
        "event_time", "logon_time", "created_at"
    ]

    ts_col = None
    for c in time_cols:
        if c in df.columns:
            ts_col = c
            break

    if ts_col:
        df["timestamp"] = pd.to_datetime(df[ts_col], errors="coerce")
    else:
        base = pd.Timestamp.now().normalize()
        df["timestamp"] = [
            base + pd.Timedelta(minutes=i)
            for i in range(len(df))
        ]

    if "user" not in df.columns:
        for c in ["user_id", "employee", "username", "account"]:
            if c in df.columns:
                df["user"] = df[c]
                break
        else:
            df["user"] = "unknown"

    if "event_type" not in df.columns:
        for c in ["activity", "action", "event", "operation"]:
            if c in df.columns:
                df["event_type"] = df[c]
                break
        else:
            df["event_type"] = "generic_event"

    if "resource" not in df.columns:
        df["resource"] = "unknown_resource"

    if "size" not in df.columns:
        df["size"] = 0

    if "src_ip" not in df.columns:
        df["src_ip"] = "0.0.0.0"

    if "dst_ip" not in df.columns:
        df["dst_ip"] = "0.0.0.0"

    df = df.dropna(subset=["timestamp"])
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["date"] = df["timestamp"].dt.date

    df["user"] = df["user"].astype(str).str.lower()
    df["event_type"] = df["event_type"].astype(str).str.lower()
    return df

def add_mitre_columns(df):
    df = df.copy()
    tactics = []
    techniques = []
    for et in df["event_type"].astype(str).str.lower():
        tactic, tech = MITRE_EVENT_MAP.get(et, ("Unknown", "Unknown"))
        tactics.append(tactic)
        techniques.append(tech)
    df["mitre_tactic"] = tactics
    df["mitre_technique"] = techniques
    return df

def aggregate_per_user_day(df):
    agg = df.groupby(['user','date']).agg(
        total_events=('event_type','count'),
        distinct_resources=('resource', pd.Series.nunique),
        bytes_transferred=('size','sum')
    ).reset_index()
    def avg_interval(sub):
        times = sub['timestamp'].sort_values()
        if len(times) <= 1: return 0.0
        diffs = times.diff().dt.total_seconds().dropna()
        return float(diffs.mean()) if len(diffs) else 0.0
    avg_int = df.groupby(['user','date']).apply(avg_interval).rename('avg_event_interval').reset_index()
    agg = agg.merge(avg_int, on=['user','date'], how='left')
    df['failed_login_flag'] = (df['event_type'].str.lower().isin(['login_fail','failed_login','login_failed'])).astype(int)
    df['file_read_flag'] = (df['event_type'].str.lower().isin(['file_read','read_file'])).astype(int)
    failed = df.groupby(['user','date'])['failed_login_flag'].sum().rename('num_failed_logins').reset_index()
    reads  = df.groupby(['user','date'])['file_read_flag'].sum().rename('num_file_reads').reset_index()
    agg = agg.merge(failed, on=['user','date'], how='left').merge(reads, on=['user','date'], how='left')
    agg[['num_failed_logins','num_file_reads','distinct_resources','bytes_transferred','avg_event_interval']] = \
        agg[['num_failed_logins','num_file_reads','distinct_resources','bytes_transferred','avg_event_interval']].fillna(0)
    return agg

def compute_temporal_features(agg_df):
    df = agg_df.copy().sort_values(['user','date'])
    df['total_events_last_7d'] = df.groupby('user')['total_events'].rolling(window=7,min_periods=1).sum().reset_index(0,drop=True)
    df['total_events_delta_1d'] = df.groupby('user')['total_events'].diff().fillna(0)
    roll_mean = df.groupby('user')['total_events'].rolling(window=30,min_periods=1).mean().reset_index(0,drop=True)
    roll_std  = df.groupby('user')['total_events'].rolling(window=30,min_periods=1).std().reset_index(0,drop=True).replace(0, np.nan)
    df['zscore_30d'] = ((df['total_events'] - roll_mean) / roll_std).fillna(0)
    return df

def compute_graph_features(df, agg_df):
    agg = agg_df.copy()
    if not HAS_NETWORKX:
        agg['user_centrality'] = 0.0
        return agg
    try:
        G = nx.Graph()
        users = df['user'].unique().tolist()
        resources = df['resource'].unique().tolist()
        G.add_nodes_from(users, bipartite=0)
        G.add_nodes_from(resources, bipartite=1)
        edges = df[['user','resource']].drop_duplicates().values.tolist()
        G.add_edges_from(edges)
        centrality = nx.algorithms.bipartite.degree_centrality(G, users)
        agg['user_centrality'] = agg['user'].map(lambda u: centrality.get(u, 0.0))
    except Exception:
        agg['user_centrality'] = 0.0
    return agg

def compute_mitre_summary(df):
    summary = (
        df.groupby(["user", "date", "mitre_tactic"])
        .size()
        .rename("count")
        .reset_index()
    )

    pivot = summary.pivot_table(
        index=["user", "date"],
        columns="mitre_tactic",
        values="count",
        fill_value=0
    ).reset_index()

    return pivot

class Predictor:
    def __init__(self, users=None, threshold=DEFAULT_RISK_THRESHOLD):
        self.users = users if users is not None else []
        self.risk_scores = {u: 0 for u in self.users}
        self.event_log = []
        self.incident_log = []
        self.threshold = threshold
        self.activity_rules = {
            'file_download':5,'access_sensitive_folder':10,'after_hours_login':5,
            'login_from_unusual_ip':8,'data_copy_to_usb':15,'unusual_communication':7,
            'system_config_change':12,'file_delete':10,'login_fail':2,'file_read':1,'file_write':3
        }
        self.max_event_log = 200

    def _get_weight(self, event_type):
        return self.activity_rules.get(event_type, 2)

    def process_event(self, event):
        user = event.get('user', 'unknown')
        et = event.get('event_type','').lower()
        timestamp = event.get('timestamp', datetime.utcnow())
        if user not in self.risk_scores:
            self.risk_scores[user] = 0
        delta = self._get_weight(et)
        self.risk_scores[user] += delta
        ev_entry = {'timestamp':timestamp,'user':user,'event_type':et,'resource':event.get('resource','')}
        self.event_log.insert(0, ev_entry)
        if len(self.event_log) > self.max_event_log:
            self.event_log.pop()
        if self.risk_scores[user] >= self.threshold:
            incident = {'timestamp':timestamp,'user':user,'risk_score':self.risk_scores[user],'message':f'User {user} crossed threshold ({self.risk_scores[user]}) via {et}','event':ev_entry}
            self.incident_log.insert(0, incident)
            self.risk_scores[user] = 0

    def process_events_bulk(self, df):
        for _, row in df.sort_values('timestamp').iterrows():
            self.process_event({'timestamp': row['timestamp'], 'user': row['user'], 'event_type': row['event_type'], 'resource': row['resource']})

    def get_top_risks(self, top_n=10):
        return sorted(self.risk_scores.items(), key=lambda x: x[1], reverse=True)[:top_n]

def run_isolation_forest(agg_df, feature_cols=None, contamination=0.05):
    if feature_cols is None:
        feature_cols = ['total_events','distinct_resources','bytes_transferred','num_failed_logins','num_file_reads','user_centrality','zscore_30d']
    feat = agg_df.reindex(columns=feature_cols).fillna(0).values
    scaler = StandardScaler()
    try:
        Xs = scaler.fit_transform(feat)
    except Exception:
        Xs = feat
    iso = IsolationForest(n_estimators=200, contamination=contamination, random_state=42)
    iso.fit(Xs)
    scores = iso.decision_function(Xs)
    preds = iso.predict(Xs)
    out = agg_df.copy()
    out['anomaly_score'] = scores
    out['is_anomaly'] = (preds == -1)
    return out

def prepare_sequences_for_lstm(agg_df, feature_cols, lookback=7):
    seqs = []
    labels = []
    user_risk_map = {}

    for user in agg_df['user'].unique():
        g = agg_df[agg_df['user'] == user]
        risky_days = (
            (g['num_failed_logins'] >= 8) |
            (g['bytes_transferred'] >= g['bytes_transferred'].median() * 5) |
            (g['total_events'] >= g['total_events'].median() * 4)
        )
        user_risk_map[user] = int(risky_days.sum() >= 5)
    for user in agg_df['user'].unique():
        g = agg_df[agg_df['user'] == user].sort_values('date')
        mat = g[feature_cols].fillna(0).values

        label = user_risk_map[user]

        for i in range(len(mat) - lookback):
            seqs.append(mat[i:i + lookback])
            labels.append(label)

    return np.array(seqs), np.array(labels)

def build_lstm_model(input_shape):
    model = Sequential([
        LSTM(64, return_sequences=True, input_shape=input_shape),
        Dropout(0.3), LSTM(32), Dropout(0.2), Dense(1, activation="sigmoid")
    ])
        
    model.compile(
        optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"]
    )
    return model

class HoverImageCard(tk.Frame):
    def __init__(self, parent, image_path, title, desc, on_click=None):
        super().__init__(parent, bg="#0f2433", width=360, height=300)
        self.pack_propagate(False)

        self._img_ref = None
        self.on_click = on_click

        canvas = tk.Canvas(self, width=360, height=220,
                           bg="#0f2433", highlightthickness=0)
        canvas.pack()

        if os.path.exists(image_path):
            try:
                img = Image.open(image_path).resize((360, 220), Image.Resampling.LANCZOS)
                self._img_ref = ImageTk.PhotoImage(img)
                canvas.create_image(0, 0, image=self._img_ref, anchor="nw")
            except Exception:
                canvas.create_rectangle(0, 0, 360, 220, fill="#102c40")
                canvas.create_text(180, 110, text="Image Load Error", fill="#9fd6ff", font=("Segoe UI", 12))
        else:
            canvas.create_rectangle(0, 0, 360, 220, fill="#102c40")
            canvas.create_text(180, 110, text="Image Not Found",
                               fill="#9fd6ff", font=("Segoe UI", 12))

        overlay = canvas.create_rectangle(
            0, 0, 360, 220, fill="#000", stipple="gray25", state="hidden"
        )

        title_lbl = tk.Label(self, text=title,
                             bg="#0f2433", fg="#eaf9ff",
                             font=("Segoe UI", 14, "bold"))
        title_lbl.pack(pady=(8, 4))

        info_lbl = tk.Label(self, text=desc,
                            bg="#071a27", fg="#9fd6ff",
                            wraplength=320, justify="center",
                            padx=10, pady=8)

        def on_enter(_):
            canvas.itemconfigure(overlay, state="normal")
            info_lbl.pack(pady=4)

        def on_leave(_):
            canvas.itemconfigure(overlay, state="hidden")
            info_lbl.pack_forget()

        def on_click_event(_):
            try:
                if callable(self.on_click):
                    self.on_click()
            except Exception:
                traceback.print_exc()
        for w in (canvas, self, title_lbl):
            w.bind("<Enter>", on_enter)
            w.bind("<Leave>", on_leave)
            w.bind("<Button-1>", on_click_event)

class InsiderDashboardAligned:
    def __init__(self, root):
        self.root = root
        self.root.title("Insider Threat Predictor")
        try:
            self.root.state('zoomed')  
        except Exception:
            sw = self.root.winfo_screenwidth(); sh = self.root.winfo_screenheight()
            self.root.geometry(f"{sw}x{sh}+0+0")
        self.status_var = tk.StringVar(value="Ready")
        self.var_lookback = tk.IntVar(value=7)
        self.raw_df = pd.DataFrame()
        self.agg_df = pd.DataFrame()
        self.agg_enriched = pd.DataFrame()
        self.predictor = Predictor(threshold=DEFAULT_RISK_THRESHOLD)
        self.anom_df = pd.DataFrame()
        self.popups = {}  
        self.bg_color = "#0b1622"
        self.card_color = "#0f2433"
        self.sidebar_color = "#07111a"
        self.btn_bg = "#0b63d6"
        self.btn_fg = "#ffffff"
        self._home_imgs = []
        self._build_ui()

    def _add_home_images(self):
        container = tk.Frame(self.home_frame, bg=self.bg_color)
        container.pack(fill=tk.BOTH, expand=True)

        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        row = tk.Frame(container, bg=self.bg_color)
        row.grid(row=0, column=0)

        cards = [
            (
                IMG_1,
                "Basic Info",
                "Analyze user behavior and identify insider threats.",
                self._show_code_popup
            ),
            (
                IMG_2,
                "Project Flow",
                "Logs → Aggregation → Feature Engineering → Detection.",
                self._open_html_report
            ),
            (
                IMG_3,
                "About ME",
                "Developed by Shaikh Aiman",
                self._show_about_me
            ),
        ]

        for img, title, desc, action in cards:
            card = HoverImageCard(
                row,
                img,
                title,
                desc,
                on_click=action
            )
            card.pack(side=tk.LEFT, padx=30)
            self._home_imgs.append(card)

    def _show_code_popup(self):
        name = "Code Explanation"

        if name in self.popups and self.popups[name].winfo_exists():
            win = self.popups[name]
            win.deiconify()
            win.lift()
            return

        win = tk.Toplevel(self.root)
        win.title("Code Explanation")
        self._center_window(win, 800, 600)
        win.configure(bg=self.card_color)
        self.popups[name] = win

        tk.Label(
            win,
            text="Insider Threat Predictor — Code Overview",
            bg=self.card_color,
            fg="#d7eefc",
            font=("Segoe UI", 14, "bold")
        ).pack(pady=(10, 6))

        text = tk.Text(
            win,
            wrap=tk.WORD,
            bg="#071a27",
            fg="#eaf9ff",
            padx=14,
            pady=14
        )
        text.pack(fill=tk.BOTH, expand=True)

        text.insert(tk.END, """Project Overview
The Insider Threat Predictor is a security analytics application designed to monitor internal user activity and identify potential insider threats.
The system analyzes event logs, builds behavioral patterns for users, detects anomalies, and assigns risk scores to highlight suspicious behavior.
It is intended for academic research, SOC simulation, and security analysis.

System Architecture Overview
The application follows a structured workflow:
• Event logs are ingested from CSV files or generated synthetically
• User activity is aggregated on a per-user, per-day basis
• Behavioral and temporal features are computed
• Risk scores are calculated using security rules
• Machine learning models detect abnormal behavior
• Results are visualized using tables, charts, and reports

Main Toolbar Functions
Load CSV
Loads a real-world event log file in CSV format. The file may include login events, file operations, network activity, or system actions.

Generate Sample
Creates a realistic synthetic dataset with normal users and simulated insider behavior. This is useful for testing and demonstration without real data.

Recompute Aggregates
Groups raw events into daily summaries per user. This step prepares the data for feature extraction and analysis.

Compute Enriched Features
Calculates advanced features such as event frequency, failed login counts, data transfer volume, and behavioral deviations.

Clear Data
Resets all loaded data, computed features, risk scores, and model results. Use this before starting a new analysis session.

Sidebar Sections and Controls
Aggregates
• Load CSV – Load event data
• Recompute Aggregates – Generate user/day summaries
• Compute Enriched Features – Extract behavioral metrics
• Show Aggregates Table – View aggregated data

Prediction
• Run Event Processor – Applies rule-based risk scoring
• Show Recent Events – Displays latest processed activities
• Show Incidents – Lists users who crossed the risk threshold
• Show Risk Scores – Displays current risk values per user

Anomaly Detection
• Run Isolation Forest – Detects abnormal user behavior
• Show Top Anomalies – Displays suspicious users
• Export Anomalies – Saves anomaly results as CSV

Risk Scores
• Show Risk Chart – Bar chart of user risk levels
• Show Risk Table – Tabular view of risk scores
• Show MITRE Heatmap – Visualizes activity mapped to MITRE ATT&CK tactics

Model Train
• Train LSTM – Trains a temporal prediction model
• Predict Insider Risk – Predicts insider risk probability
• Show LSTM Classification – Displays risk categories
• Show LSTM Alerts – Lists high-risk users detected by LSTM

Risk Scoring Logic
Each user activity is assigned a weight based on its security impact.
High-risk actions such as data exfiltration, system changes, and repeated
authentication failures increase the risk score.
When a user crosses the predefined threshold, an incident is generated.

Machine Learning Models Used
Isolation Forest
Detects unusual user behavior without requiring labeled attack data.

LSTM Model
Learns historical user behavior patterns and predicts future insider risk based on temporal activity sequences.

Important Notes
• Always recompute aggregates after loading new data
• Enriched features must be computed before running ML models
• LSTM training requires sufficient historical data
• Export options save results for reporting and documentation

           
How to Operate:
           
1. Start the application and wait for the home screen to load.
2. Load a CSV file or generate sample data.
3. Click "Recompute Aggregates" to prepare the data.
4. Click "Compute Enriched Features" to extract behavior metrics.
5. Run Event Processor or Isolation Forest for analysis.
6. View results using tables, charts, or heatmaps.
7. (Optional) Train the LSTM model for predictive analysis.
8. Export reports if needed.
9. Use "Clear Data" before starting a new analysis."""
            
)

    def _show_about_me(self):
        win = tk.Toplevel(self.root)
        win.title("About the Developer")
        self._center_window(win, 600, 380)
        win.configure(bg=self.card_color)

        text = tk.Text(
            win,
            wrap=tk.WORD,
            bg=self.card_color,
            fg="#d7eefc",
            font=("Segoe UI", 11),
            padx=14,
            pady=14
        )
        text.pack(fill=tk.BOTH, expand=True)

        text.insert(tk.END, """Shaikh Aiman
Cybersecurity Engineer | Insider Threat & UEBA Systems

I am a cybersecurity-focused engineer with hands-on experience in designing and implementing insider threat detection systems.
My work emphasizes understanding user behavior, identifying security anomalies, and translating complex data into actionable insights.

This project reflects my practical approach to cybersecurity, combining log analysis, behavioral modeling, risk scoring, and machine learning to simulate real-world SOC operations. The system is designed not only to detect suspicious activity but also to present findings in a clear and investigative manner.

I am particularly interested in security analytics, threat detection, and defensive security systems, with a strong focus on building tools that are realistic, explainable, and operationally useful.

This project was developed for academic research, technical evaluation,and SOC-style simulations, demonstrating applied cybersecurity skills rather than theoretical concepts.

I would like to express my sincere gratitude to Supraja Technologies for providing valuable guidance, technical exposure, and a supportive learning environment throughout the development of this project. Their mentorship and industry-oriented approach played an important role in shaping the design, implementation, and practical relevance of this work.
""")

        text.configure(state="disabled")
        
    def _open_html_report(self):
        try:
            html_src = resource_path("assets/ProjectReport.html")
    
            temp_dir = tempfile.mkdtemp()
            html_dst = os.path.join(temp_dir, "ProjectReport.html")
    
            shutil.copy(html_src, html_dst)
    
            # copy all required html assets
            for f in ["Sidebar_LOGO.jpg"]:
                shutil.copy(
                    resource_path(f"assets/{f}"),
                    os.path.join(temp_dir, f)
                )
    
            webbrowser.open(f"file:///{html_dst}")
    
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open report:\n{e}")

    def _build_ui(self):
        self.main = tk.Frame(self.root, bg=self.bg_color)
        self.main.pack(fill=tk.BOTH, expand=True)
        self.sidebar_w = 180
        self.sidebar = tk.Frame(self.main, width=self.sidebar_w, bg=self.sidebar_color)
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y)
        self.sidebar.pack_propagate(False)
    
        LOGO_IMG = resource_path("assets/Sidebar_LOGO.jpg")
        from PIL import Image, ImageTk
        
        try:
            logo_img = Image.open(LOGO_IMG).resize((140, 140), Image.Resampling.LANCZOS)
            self.logo_ref = ImageTk.PhotoImage(logo_img)
        
            logo_lbl = tk.Label(
                self.sidebar,
                image=self.logo_ref,
                bg=self.sidebar_color
            )
            logo_lbl.pack(pady=(18, 10))
        
        except Exception as e:
            tk.Label(
                self.sidebar,
                text="INSIDEO",
                bg=self.sidebar_color,
                fg="#9fd6ff",
                font=("Segoe UI", 16, "bold")
            ).pack(pady=(18, 10))
            tk.Label(
                self.sidebar,
                text="See the Threat Within",
                bg=self.sidebar_color,
                fg="#90c7ff",
                font=("Segoe UI", 9)
            ).pack(pady=(0, 14))
          
        self.sections = ["Aggregates", "Prediction", "Anomaly Detection", "Risk Scores", "Model Train"]
        self.section_frames = {}
        for sec in self.sections:
            btn = tk.Button(self.sidebar, text=sec, anchor="w", relief=tk.FLAT, bd=0, padx=16, pady=12,
                            bg=self.sidebar_color, fg="#d7eefc", activebackground="#112733", cursor="hand2",
                            font=("Segoe UI", 10, "bold"),
                            command=lambda s=sec: self._on_section_click(s))
            btn.pack(fill=tk.X, pady=(0,6))

        self.content = tk.Frame(self.main, bg=self.bg_color)
        self.content.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=12, pady=(6,12))
        toolbar = tk.Frame(self.content, bg=self.bg_color)
        toolbar.pack(side=tk.TOP, fill=tk.X, padx=6, pady=6)
        tk.Button(toolbar, text="Load CSV", command=self.gui_load_csv, bg=self.btn_bg, fg=self.btn_fg, bd=0, padx=10, pady=6).pack(side=tk.LEFT, padx=6)
        tk.Button(toolbar, text="Generate Sample", command=self._generate_sample_data, bg=self.btn_bg, fg=self.btn_fg, bd=0, padx=10, pady=6).pack(side=tk.LEFT, padx=6)
        tk.Button(toolbar, text="Recompute Aggregates", command=self._recompute_aggregates, bg=self.btn_bg, fg=self.btn_fg, bd=0, padx=10, pady=6).pack(side=tk.LEFT, padx=6)
        tk.Button(toolbar, text="Compute Enriched", command=self._compute_enriched_features, bg=self.btn_bg, fg=self.btn_fg, bd=0, padx=10, pady=6).pack(side=tk.LEFT, padx=6)
        tk.Button(toolbar, text="Clear Data", command=self._clear_data, bg=self.btn_bg, fg=self.btn_fg, bd=0, padx=10, pady=6).pack(side=tk.LEFT, padx=6)
        status_bar = tk.Frame(self.root, bg="#061018")
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        tk.Label(status_bar, textvariable=self.status_var, bg="#061018", fg="#9fd6ff", anchor="w").pack(side=tk.LEFT, padx=8, pady=6)
        
        self.home_frame = tk.Frame(self.content, bg=self.bg_color)
        self.home_frame.pack(fill=tk.BOTH, expand=True)
        self._add_home_images()
        self.home_frame.lift()

    def _on_section_click(self, section):
       self.open_section_popup(section)

    def show_section(self, name):
        for sec, frame in self.section_frames.items():
            if sec == name: frame.lift()
            else: frame.lower()
        self.status_var.set(f"Viewing: {name}")

    def open_section_popup(self, section):
        if section in self.popups and self.popups[section].winfo_exists():
            self.popups[section].deiconify()
            self.popups[section].lift()
            return
        popup = tk.Toplevel(self.root)
        popup.title(f"{section} Controls")
        popup.geometry("700x450")
        self._center_window(popup, 700, 450)
        popup.configure(bg=self.card_color)
        self.popups[section] = popup

        def on_close():
            try:
                del self.popups[section]
            except Exception:
                pass
            popup.destroy()
        popup.protocol("WM_DELETE_WINDOW", on_close)

        tk.Label(popup, text=f"{section} Controls", bg=self.card_color, fg="#d7eefc", font=("Segoe UI", 14, "bold")).pack(pady=(12,8))

        body = tk.Frame(popup, bg=self.card_color)
        body.pack(fill=tk.BOTH, expand=True, padx=12, pady=(4,12))

        def grid_btn(row, col, text, cmd, colspan=1):
            btn = tk.Button(body, text=text, command=cmd, bd=0, bg=self.btn_bg, fg=self.btn_fg, activebackground="#085aa8",
                            padx=12, pady=10)
            btn.grid(row=row, column=col, columnspan=colspan, sticky="nsew", padx=8, pady=8)
            return btn
        body.grid_columnconfigure(0, weight=1)
        body.grid_columnconfigure(1, weight=1)
        if section == "Aggregates":
            grid_btn(0, 0, "Load CSV", self.gui_load_csv)
            grid_btn(0, 1, "Recompute Aggregates", self._recompute_aggregates)
            grid_btn(1, 0, "Compute Enriched Features", self._compute_enriched_features)
            grid_btn(1, 1, "Clear Data", self._clear_data)
            grid_btn(2, 0, "Show Aggregates Table", self._show_aggregates_table, colspan=2)

        elif section == "Prediction":
            grid_btn(0, 0, "Run Event Processor", self._run_event_processor)
            grid_btn(0, 1, "Show Recent Events", self._show_recent_events)
            grid_btn(1, 0, "Show Incidents", self._show_incidents)
            grid_btn(1, 1, "Show Risk Scores (quick)", self._show_risks_quick)

        elif section == "Anomaly Detection":
            grid_btn(0, 0, "Run Isolation Forest", self._run_isolation)
            grid_btn(0, 1, "Show Top Anomalies", self._show_anomalies)
            grid_btn(1, 0, "Export Anomalies (CSV)", self._export_anomalies_csv, colspan=2)


        elif section == "Risk Scores":
            grid_btn(0, 0, "Show Risk Chart", self._plot_risk)
            grid_btn(0, 1, "Show Risk Table", self._show_risk_table)
            grid_btn(1, 0, "Export Risk Table", self._export_risk_table_csv, colspan=2)
            grid_btn(2, 0, "Show MITRE Heatmap", self._show_mitre_heatmap, colspan=2)


        elif section == "Model Train":
            lbl = tk.Label(body, text="Lookback (days):", bg=self.card_color, fg="#d7eefc")
            lbl.grid(row=0, column=0, sticky="w", padx=8, pady=8)
            popup_look = tk.IntVar(value=self.var_lookback.get())
            ent = tk.Entry(body, width=6, textvariable=popup_look)
            ent.grid(row=0, column=1, sticky="w", padx=8, pady=8)
            if not HAS_TF:
                grid_btn(1, 0, "Train LSTM (Unavailable)", lambda: messagebox.showwarning("Unavailable","TensorFlow not available"), colspan=2)
            else:
                def train_cmd():
                    self.var_lookback.set(popup_look.get()); self._train_lstm()
                grid_btn(1, 0, "Train LSTM", train_cmd, colspan=2)
                grid_btn(2, 0,"Predict Insider Risk (LSTM)",self._predict_lstm_risk,colspan=2)
                grid_btn( 3, 0,"Show LSTM Classification",self._show_lstm_predictions,colspan=2)
                grid_btn(4, 0,"Show LSTM Alerts",self._show_lstm_alerts,colspan=2)
   
        close = tk.Button(popup, text="Close", command=on_close, bd=0, bg="#555555", fg="#ffffff", padx=10, pady=6)
        close.pack(side=tk.BOTTOM, pady=(0,8))

    def _center_window(self, win, w, h):
        sw = win.winfo_screenwidth(); sh = win.winfo_screenheight()
        x = (sw - w) // 2; y = (sh - h) // 2
        win.geometry(f"{w}x{h}+{x}+{y}")
     
    def _export_anomalies_csv(self):
        if self.anom_df is None or self.anom_df.empty:
            messagebox.showwarning("No data", "No anomalies to export.")
            return

        path = filedialog.asksaveasfilename(
            title="Save Anomalies CSV",
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv")]
        )
        if not path:
            return

        self.anom_df.to_csv(path, index=False)
        messagebox.showinfo("Export Successful", f"Anomalies exported to:\n{path}")


    def _export_risk_table_csv(self):
        if not self.predictor.risk_scores:
            messagebox.showwarning("No data", "No risk scores to export.")
            return

        df = pd.DataFrame(
            self.predictor.risk_scores.items(),
            columns=["user", "risk_score"]
        ).sort_values("risk_score", ascending=False)

        path = filedialog.asksaveasfilename(
            title="Save Risk Scores CSV",
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv")]
        )
        if not path:
            return

        df.to_csv(path, index=False)
        messagebox.showinfo("Export Successful", f"Risk scores exported to:\n{path}")

    def gui_load_csv(self):
        path = filedialog.askopenfilename(title="Select events CSV", filetypes=[("CSV Files","*.csv"),("All files","*.*")])
        if not path:
            return
        try:
            self.status_var.set("Loading CSV...")
            df = load_csv(path)
            df = add_mitre_columns(df)
            self.raw_df = df
            self.agg_df = aggregate_per_user_day(df)
            self.agg_enriched = compute_temporal_features(self.agg_df)
            self.agg_enriched = compute_graph_features(self.raw_df, self.agg_enriched)
            self.status_var.set(f"Loaded {len(df)} events, {len(self.agg_df)} aggregated rows.")
            messagebox.showinfo("Loaded", f"Loaded {len(df)} events.")
        except Exception as e:
            traceback.print_exc()
            messagebox.showerror("Load Error", str(e))
            self.status_var.set("Failed to load CSV.")

    def _generate_sample_data(self):
        import random
    
        users = ['user_a','user_b','user_c','user_d','user_e']
        attacker_users = random.sample(users, 2)  
    
        resources = [f'resource_{i}' for i in range(1,21)]
        event_types = [
            'file_read','file_write','login_success',
            'login_fail','file_delete','file_download',
            'system_config_change'
        ]
    
        rows = []
        now = pd.Timestamp.now().normalize()
    
        for day_offset in range(45):
            day = now - pd.Timedelta(days=day_offset)
    
            for user in users:
                is_attacker = user in attacker_users and day_offset < 10
    
                if is_attacker:
                    num = random.randint(30, 60)  
                    num = random.randint(5, 15)
    
                for _ in range(num):
                    ts = day + pd.Timedelta(seconds=random.randint(1, 86400))
    
                    if is_attacker:
                        et = random.choices(
                            ['login_fail','file_download','file_delete','system_config_change'],
                            weights=[40, 30, 20, 10]
                        )[0]
                        size = random.randint(1024*50, 1024*500)  
                    else:
                        et = random.choice(event_types)
                        size = random.randint(0, 1024*20)
    
                    rows.append({
                        'timestamp': ts,
                        'user': user,
                        'event_type': et,
                        'resource': random.choice(resources),
                        'size': size,
                        'src_ip': f"10.0.{random.randint(0,255)}.{random.randint(1,254)}",
                        'dst_ip': f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"
                    })
    
        df = pd.DataFrame(rows).sample(frac=1).reset_index(drop=True)
        df['date'] = df['timestamp'].dt.date
    
        df = add_mitre_columns(df)
    
        self.raw_df = df
        self.agg_df = aggregate_per_user_day(df)
        self.agg_enriched = compute_temporal_features(self.agg_df)
        self.agg_enriched = compute_graph_features(self.raw_df, self.agg_enriched)
    
        messagebox.showinfo(
            "Sample Data Generated",
            f"Events: {len(df)}"
        )
    
    

    def _recompute_aggregates(self):
        if self.raw_df is None or self.raw_df.empty:
            messagebox.showwarning("No data", "Load data first.")
            return
        self.agg_df = aggregate_per_user_day(self.raw_df)
        self.status_var.set("Aggregates recomputed.")
        messagebox.showinfo("Aggregates", f"Recomputed {len(self.agg_df)} aggregated rows.")

    def _compute_enriched_features(self):
        if self.agg_df is None or self.agg_df.empty:
            messagebox.showwarning("No aggregates", "Compute aggregates first.")
            return
        self.agg_enriched = compute_temporal_features(self.agg_df)
        self.agg_enriched = compute_graph_features(self.raw_df, self.agg_enriched)
        self.status_var.set("Enriched features computed.")
        messagebox.showinfo("Enriched", "Enriched features computed.")

    def _clear_data(self):
        self.raw_df = pd.DataFrame(); self.agg_df = pd.DataFrame(); self.agg_enriched = pd.DataFrame()
        self.predictor = Predictor(threshold=DEFAULT_RISK_THRESHOLD)
        self.status_var.set("Data cleared.")
        messagebox.showinfo("Cleared", "All data cleared.")

    def _run_event_processor(self):
        if self.raw_df is None or self.raw_df.empty:
            messagebox.showwarning("No data", "Please load a CSV first.")
            return

        def task():
            try:
                self.status_var.set("Processing events...")
                users = list(self.raw_df['user'].unique())
                self.predictor = Predictor(users=users, threshold=DEFAULT_RISK_THRESHOLD)
                self.predictor.process_events_bulk(self.raw_df)
                self.root.after(50, self._show_event_processor_results)
            except Exception as e:
                traceback.print_exc()
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
                self.root.after(0, lambda: self.status_var.set("Error processing events."))
        threading.Thread(target=task, daemon=True).start()

    def _show_event_processor_results(self):
        name = "Event Processor Results"
        if name in self.popups and self.popups[name].winfo_exists():
            win = self.popups[name]
            win.deiconify(); win.lift()
        else:
            win = tk.Toplevel(self.root); win.title(name); win.geometry("900x600"); self._center_window(win,900,600); win.configure(bg=self.card_color); self.popups[name] = win
            win.protocol("WM_DELETE_WINDOW", lambda w=win, n=name: self._close_popup(n,w))

        for child in win.winfo_children():
            child.destroy()

        tk.Label(win, text="Event Processor Results", bg=self.card_color, fg="#d7eefc", font=("Segoe UI", 14, "bold")).pack(pady=(8,6))
        container = tk.Frame(win, bg=self.card_color); container.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        left = tk.Frame(container, bg=self.card_color); left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0,6))
        right = tk.Frame(container, bg=self.card_color); right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(6,0))

        tk.Label(left, text="Top Risk Scores", bg=self.card_color, fg="#9fd6ff", font=("Segoe UI", 11, "bold")).pack(anchor="w")
        cols = ("user","risk_score")
        tree = ttk.Treeview(left, columns=cols, show="headings", height=10)
        tree.heading("user", text="User"); tree.heading("risk_score", text="Risk Score")
        tree.column("user", width=160); tree.column("risk_score", width=100, anchor="center")
        tree.pack(fill=tk.BOTH, expand=False, pady=(6,10))
        topn = self.predictor.get_top_risks(50)
        for u,s in topn:
            tree.insert("", tk.END, values=(u, s))

        tk.Label(right, text="Recent Events (most recent first)", bg=self.card_color, fg="#9fd6ff", font=("Segoe UI", 11, "bold")).pack(anchor="w")
        ev_frame = tk.Frame(right, bg=self.card_color); ev_frame.pack(fill=tk.BOTH, expand=True, pady=(6,10))
        ev_text = tk.Text(ev_frame, wrap=tk.NONE, height=15)
        ev_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sbv = ttk.Scrollbar(ev_frame, orient=tk.VERTICAL, command=ev_text.yview)
        ev_text.configure(yscrollcommand=sbv.set); sbv.pack(side=tk.RIGHT, fill=tk.Y)
        for ev in self.predictor.event_log[:1000]:
            ev_text.insert(tk.END, f"{ev['timestamp']} | {ev['user']} | {ev['event_type']} | {ev['resource']}\n")
        ev_text.configure(state="disabled")

        inc_label = tk.Label(win, text="Incident Log", bg=self.card_color, fg="#9fd6ff", font=("Segoe UI", 11, "bold"))
        inc_label.pack(anchor="w", padx=8)
        inc_frame = tk.Frame(win, bg=self.card_color); inc_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=(4,8))
        inc_text = tk.Text(inc_frame, height=8); inc_text.pack(fill=tk.BOTH, expand=True)
        if not self.predictor.incident_log:
            inc_text.insert(tk.END, "No incidents.\n")
        else:
            for inc in self.predictor.incident_log[:500]:
                inc_text.insert(tk.END, f"{inc['timestamp']} | {inc['user']} | Score: {inc['risk_score']} | {inc['message']}\n")
        inc_text.configure(state="disabled")
        self.status_var.set(f"Processed events. Top incidents: {len(self.predictor.incident_log)}")

    def _close_popup(self, name, win):
        try:
            del self.popups[name]
        except Exception:
            pass
        win.destroy()

    def _show_recent_events(self):
        name = "Recent Events"
        if name in self.popups and self.popups[name].winfo_exists():
            win = self.popups[name]; win.deiconify(); win.lift(); return
        win = tk.Toplevel(self.root); win.title(name); win.geometry("900x500"); self._center_window(win,900,500); win.configure(bg=self.card_color); self.popups[name] = win
        win.protocol("WM_DELETE_WINDOW", lambda w=win, n=name: self._close_popup(n,w))
        txt = tk.Text(win); txt.pack(fill=tk.BOTH, expand=True)
        if not self.predictor.event_log:
            txt.insert(tk.END, "No events processed yet.\n")
        else:
            for ev in self.predictor.event_log[:2000]:
                txt.insert(tk.END, f"{ev['timestamp']} | {ev['user']} | {ev['event_type']} | {ev['resource']}\n")
        txt.configure(state="disabled")

    def _show_incidents(self):
        name = "Incidents"
        if name in self.popups and self.popups[name].winfo_exists():
            win = self.popups[name]; win.deiconify(); win.lift(); return
        win = tk.Toplevel(self.root); win.title(name); win.geometry("800x400"); self._center_window(win,800,400); win.configure(bg=self.card_color); self.popups[name] = win
        win.protocol("WM_DELETE_WINDOW", lambda w=win, n=name: self._close_popup(n,w))
        txt = tk.Text(win); txt.pack(fill=tk.BOTH, expand=True)
        if not self.predictor.incident_log:
            txt.insert(tk.END, "No incidents.\n")
        else:
            for inc in self.predictor.incident_log[:2000]:
                txt.insert(tk.END, f"{inc['timestamp']} | {inc['user']} | Score: {inc['risk_score']} | {inc['message']}\n")
        txt.configure(state="disabled")

    def _show_lstm_alerts(self):
        name = "LSTM Alerts"
    
        if name in self.popups and self.popups[name].winfo_exists():
            win = self.popups[name]
            win.deiconify()
            win.lift()
            return
    
        win = tk.Toplevel(self.root)
        win.title("LSTM Insider Risk Alerts")
        win.geometry("700x400")
        self._center_window(win, 700, 400)
        win.configure(bg=self.card_color)
        self.popups[name] = win
    
        txt = tk.Text(
            win,
            wrap=tk.WORD,
            bg="#071a27",
            fg="#eaf9ff",
            font=("Segoe UI", 11)
        )
        txt.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)
    
        if not hasattr(self, "lstm_alerts") or not self.lstm_alerts:
            txt.insert(tk.END, "No LSTM alerts generated.\n")
        else:
            for alert in self.lstm_alerts:
                txt.insert(tk.END, alert + "\n")
    
        txt.configure(state="disabled")
    
   
    def _show_risks_quick(self):
        top = self.predictor.get_top_risks(20)
        s = "\n".join(f"{u}: {v}" for u,v in top) if top else "No risk scores yet."
        messagebox.showinfo("Top risks", s)

    def _show_aggregates_table(self):
        name = "Aggregates Table"
        if name in self.popups and self.popups[name].winfo_exists():
            win = self.popups[name]; win.deiconify(); win.lift(); return
        win = tk.Toplevel(self.root); win.title(name); win.geometry("1000x600"); self._center_window(win,1000,600); win.configure(bg=self.card_color); self.popups[name] = win
        win.protocol("WM_DELETE_WINDOW", lambda w=win, n=name: self._close_popup(n,w))
        cols = ("user","date","total_events","distinct_resources","bytes_transferred","avg_event_interval","num_failed_logins","num_file_reads")
        tree = ttk.Treeview(win, columns=cols, show="headings")
        for c in cols:
            tree.heading(c, text=c); tree.column(c, width=120, anchor="center")
        tree.pack(fill=tk.BOTH, expand=True)
        if self.agg_df is None or self.agg_df.empty:
            return
        for _, row in self.agg_df.head(2000).iterrows():
            tree.insert("", tk.END, values=(row['user'], str(row['date']), int(row['total_events']), int(row['distinct_resources']), float(row['bytes_transferred']), float(row['avg_event_interval']), int(row['num_failed_logins']), int(row['num_file_reads'])))

    def _run_isolation(self):
        if self.agg_enriched is None or self.agg_enriched.empty:
            messagebox.showwarning("No aggregated features", "Please compute enriched aggregated features first.")
            return
        def task():
            try:
                self.status_var.set("Running Isolation Forest...")
                out = run_isolation_forest(self.agg_enriched)
                self.anom_df = out[out['is_anomaly']].sort_values('anomaly_score')
                self.root.after(0, lambda: messagebox.showinfo("IsolationForest", f"Anomalies found: {len(self.anom_df)}"))
                self.root.after(0, lambda: self.status_var.set(f"IsolationForest complete. Anomalies: {len(self.anom_df)}"))
            except Exception as e:
                traceback.print_exc(); self.root.after(0, lambda: messagebox.showerror("Error", str(e))); self.root.after(0, lambda: self.status_var.set("IsolationForest failed."))
        threading.Thread(target=task, daemon=True).start()

    def _show_anomalies(self):
        name = "Anomalies"
        if name in self.popups and self.popups[name].winfo_exists():
            win = self.popups[name]; win.deiconify(); win.lift(); return
        win = tk.Toplevel(self.root); win.title(name); win.geometry("900x500"); self._center_window(win,900,500); win.configure(bg=self.card_color); self.popups[name] = win
        win.protocol("WM_DELETE_WINDOW", lambda w=win, n=name: self._close_popup(n,w))
        txt = tk.Text(win); txt.pack(fill=tk.BOTH, expand=True)
        if self.anom_df is None or self.anom_df.empty:
            txt.insert(tk.END, "No anomalies detected.\n")
        else:
            for _, r in self.anom_df.head(2000).iterrows():
                txt.insert(tk.END, f"{r['user']} | {r['date']} | events={r['total_events']} | score={r['anomaly_score']:.4f}\n")
        txt.configure(state="disabled")

    def _plot_risk(self):
        if not self.predictor.risk_scores:
            messagebox.showinfo("No scores", "No risk scores to show. Run Prediction first.")
            return
        users = list(self.predictor.risk_scores.keys())
        scores = [self.predictor.risk_scores[u] for u in users]
        fig = plt.Figure(figsize=(10,5), dpi=PLOT_DPI)
        ax = fig.add_subplot(111)
        ax.bar(users, scores)
        ax.set_title("User Risk Scores")
        ax.set_xlabel("User"); ax.set_ylabel("Risk Score")
        win = tk.Toplevel(self.root); win.title("Risk Chart"); win.geometry("1000x600"); self._center_window(win,1000,600)
        canvas = FigureCanvasTkAgg(fig, master=win); canvas.draw(); canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def _show_mitre_heatmap(self):
        if self.raw_df is None or self.raw_df.empty:
           messagebox.showwarning("No data", "Load CSV first.")
           return

        data = (
            self.raw_df
                .groupby(["date", "mitre_tactic"])
                .size()
                .rename("count")
                .reset_index()
                .pivot_table(
                   index="date",
                   columns="mitre_tactic",
                   values="count",
                   fill_value=0
                )
        )

        fig = plt.Figure(figsize=(10,6), dpi=PLOT_DPI)
        ax = fig.add_subplot(111)

        im = ax.imshow(data.values, aspect="auto")

        ax.set_xticks(range(len(data.columns)))
        ax.set_xticklabels(data.columns, rotation=45, ha="right")
        ax.set_yticks(range(len(data.index)))
        ax.set_yticklabels(data.index.astype(str))

        ax.set_title("MITRE ATT&CK Activity Heatmap")
        fig.colorbar(im, ax=ax)

        win = tk.Toplevel(self.root)
        win.title("MITRE Heatmap")
        self._center_window(win, 900, 600)

        canvas = FigureCanvasTkAgg(fig, master=win)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)


    def _show_risk_table(self):
        name = "Risk Table"
        if name in self.popups and self.popups[name].winfo_exists():
            win = self.popups[name]; win.deiconify(); win.lift(); return
        win = tk.Toplevel(self.root); win.title(name); win.geometry("600x500"); self._center_window(win,600,500); win.configure(bg=self.card_color); self.popups[name] = win
        win.protocol("WM_DELETE_WINDOW", lambda w=win, n=name: self._close_popup(n,w))
        txt = tk.Text(win); txt.pack(fill=tk.BOTH, expand=True)
        top = self.predictor.get_top_risks(200)
        if not top: txt.insert(tk.END, "No risk scores yet.\n")
        else:
            for u,s in top: txt.insert(tk.END, f"{u}: {s}\n")
        txt.configure(state="disabled")

    def _train_lstm(self):
        if not HAS_TF:
            messagebox.showwarning(
                "TensorFlow not available",
                "Install TensorFlow to enable LSTM training."
            )
            return
    
        if self.agg_enriched.empty:
            messagebox.showwarning(
                "No Data",
                "Compute enriched features first."
            )
            return
    
        lookback = int(self.var_lookback.get())
    
        FEATURE_COLS = [
            "total_events",
            "distinct_resources",
            "bytes_transferred",
            "num_failed_logins",
            "num_file_reads",
            "user_centrality",
            "zscore_30d"
        ]
    
        X, y = prepare_sequences_for_lstm(
            self.agg_enriched,
            FEATURE_COLS,
            lookback
        )
    
        if len(X) == 0:
            messagebox.showwarning(
                "Insufficient Data",
                "Not enough sequences for LSTM."
            )
            return
    
        model = build_lstm_model(
            (X.shape[1], X.shape[2])
        )
    
        model.fit(
            X, y,
            epochs=15,
            batch_size=32,
            verbose=1
        )
    
        self.lstm_model = model
        messagebox.showinfo(
            "LSTM Training",
            "LSTM model trained successfully."
        )
    
    def _predict_lstm_risk(self):
        if not hasattr(self, "lstm_model"):
            messagebox.showwarning("No Model", "Train LSTM first.")
            return
    
        FEATURE_COLS = [
            "total_events",
            "distinct_resources",
            "bytes_transferred",
            "num_failed_logins",
            "num_file_reads",
            "user_centrality",
            "zscore_30d"
        ]
    
        lookback = int(self.var_lookback.get())
        predictions = []
    
        for user in self.agg_enriched["user"].unique():
            user_df = self.agg_enriched[self.agg_enriched["user"] == user].sort_values("date")
    
            if len(user_df) < lookback:
                continue
    
            seq = user_df[FEATURE_COLS].tail(lookback).values
            seq = np.expand_dims(seq, axis=0)
    
            prob = float(self.lstm_model.predict(seq, verbose=0)[0][0])
            predictions.append((user, prob))
    
        self.lstm_predictions = predictions
        self._show_lstm_predictions()
    
        self.lstm_alerts = []
        
        for user, prob in self.lstm_predictions:
            if prob >= 0.5:
                self.lstm_alerts.append(
                    f"[ALERT] {user} high insider risk (prob={prob:.2f})"
                )    
        
    def _show_lstm_predictions(self):
        win = tk.Toplevel(self.root)
        win.title("Predictive Insider Risk (LSTM)")
        self._center_window(win, 600, 400)
    
        text = tk.Text(win)
        text.pack(fill=tk.BOTH, expand=True)
    
        for user, prob in sorted(self.lstm_predictions, key=lambda x: x[1], reverse=True):
            if prob > 0.7:
                level = "HIGH RISK"
            elif prob > 0.4:
                level = "SUSPICIOUS"
            else:
                level = "NORMAL"
    
            text.insert(
                tk.END,
                f"{user} → Risk Probability: {prob:.2f} → {level}\n"
            )
    
        text.configure(state="disabled")
    
    def _show_lstm_alerts(self):
        if not hasattr(self, "lstm_alerts") or not self.lstm_alerts:
            messagebox.showinfo("No Alerts", "No LSTM alerts generated.")
            return
    
        win = tk.Toplevel(self.root)
        win.title("LSTM Alerts")
        self._center_window(win, 500, 300)
    
        txt = tk.Text(win, padx=10, pady=10)
        txt.pack(fill=tk.BOTH, expand=True)
    
        for alert in self.lstm_alerts:
            txt.insert(tk.END, alert + "\n")
    
        txt.configure(state="disabled")
    
def main():
    root = tk.Tk()
    app = InsiderDashboardAligned(root)
    root.mainloop()

if __name__ == "__main__":
    main()

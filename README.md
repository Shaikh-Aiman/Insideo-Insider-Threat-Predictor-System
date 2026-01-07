# Insideo - Insider Threat Predictor System
<p align="center">
  <img src="https://github.com/user-attachments/assets/685d87c3-826a-4424-a62c-ce6c8e6ebacc" alt="GUI Screenshot">
</p

Insider Threat Predictor is a data-driven system that detects and analyzes potentially malicious or risky actions performed by internal users.  
It aggregates user activity logs, extracts behavioral features, and assigns risk scores to security-relevant events.  
The system employs unsupervised anomaly detection and LSTM-based temporal modeling to surface unusual behavior and potential risks.  
An interactive GUI provides visualization, incident review, and exportable reports for analyst workflows.



### Project Objective:
The primary objective of the INSIDEO – Insider Threat Predictor project is to design and implement a comprehensive system for analyzing internal user activities and identifying potential insider security risks within an organizational environment. The project focuses on collecting and aggregating user activity logs, extracting meaningful behavioral features, and evaluating user actions through rule-based risk scoring and machine learning–based anomaly detection techniques. To support deeper analysis, the system incorporates sequential behavior modeling to study user activity trends over time and highlight risky behavioral patterns. Additionally, the project aims to provide an interactive, SOC-style graphical interface that enables analysts to visualize risk scores, detected anomalies, and MITRE ATT&CK mappings, as well as export risk tables, anomaly reports, and analytical results in standard formats for further investigation, documentation, and reporting purposes.





### Modules:
- **Data Ingestion & Aggregation:** Load CSV logs or generate synthetic samples and compute per-user, per-day aggregates.  
- **Feature Engineering:** Compute behavioral metrics (counts, time-of-day patterns, resource diversity, graph metrics).  
- **Rule-Based Risk Scoring:** Apply weighted rules to events to compute base risk scores.  
- **Anomaly Detection:** Use Isolation Forest to find users whose behavior deviates from the baseline.  
- **Temporal Modeling:** Train and use an LSTM to analyze sequences of user behavior for trend-based risk prediction.  
- **Visualization & Reporting:** Generate charts, tables, MITRE heatmaps, and exportable CSV/HTML reports.  
- **Utilities & UI:** Threading, file dialogs, logging, and a Tkinter GUI that ties the flow together.


### Files Description:
- `main.py`: Main application entry point and GUI controller.  
- `INSIDEO.spec`: PyInstaller build configuration (keeps build settings reproducible).  
- `exe_logo.ico`: Application icon used when building the executable.  
- `assets/`: Images and static resources used by the GUI and documentation (screenshots, logos).  
- `docs/INSIDEO_Project_Report.pdf`: Full project report and documentation (stored in `docs/`).  
- `Visual_Overview.md`: GUI walkthrough and visual guide (placed at repository root).  
- `.gitignore`: Excludes build artifacts (`dist/`, `build/`, caches) from the repository.  
- `dist/` (not committed): Contains compiled executable (distributed via Releases).  
- `build/` (not committed): PyInstaller intermediate artifacts (optional, for debugging/build reproduction).



### Installation:
To run this project locally, follow these steps:

- __Clone the repository:__ <br>


         git clone https://github.com/Shaikh-Aiman/Insideo-Insider-Threat-Predictor-System

- __Navigate to the project directory:__
cd Insideo-Insider-Threat-Predictor-System
- __Ensure you have Python installed on your system.__
- __Install the required dependencies.__
- __Run the application:__
    `python main.py`

---

### Working:

- User activity logs are loaded into the system either through CSV files or by generating synthetic datasets that simulate insider behavior.
- The system aggregates raw logs on a per-user, per-day basis to create structured behavioral summaries for each user.
- Enriched behavioral features are computed from the aggregated data, capturing usage patterns, access frequency, and activity deviations.
- A rule-based risk scoring engine evaluates security-relevant events using predefined weight parameters to calculate individual user risk scores.
- Anomaly detection is performed using the Isolation Forest algorithm to identify users whose behavior deviates significantly from established patterns.
- Detected events are mapped to corresponding MITRE ATT&CK tactics and techniques to provide standardized threat context.
- Risk scores, anomalies, and incident details are visualized through tables, charts, and heat maps within the graphical user interface.
- The system allows exporting of risk reports, anomaly findings, and analytical results in CSV format for further investigation and documentation.
- Advanced analysis can be performed by training an LSTM model on historical behavioral sequences to evaluate temporal behavior trends and classify insider risk levels.
- The entire process is controlled through an interactive GUI, enabling monitoring, analysis, and reporting in a structured workflow.
<p align="center">
  <img 
    src="https://github.com/user-attachments/assets/7c237200-de3f-4886-bd16-0d1fc6fbcb80" alt="GUI Screenshot" width="600">
</p>



---

### Download Executable:
The compiled Windows executable (.exe) for the INSIDEO application is available in the GitHub Releases section of this repository. Users can download the executable package (INSIDEO_dist.zip) from the latest release and run the application without requiring a Python environment.

__Release Link:__
👉 https://github.com/Shaikh-Aiman/Insideo-Insider-Threat-Predictor-System/releases

<p align="center">
  <img 
    src="https://github.com/user-attachments/assets/7d4c2527-d95c-4f80-944f-f3469d12393d" alt="Demo GIF" style="max-width: 100%; height: auto;"/>
</p>


---
### Usage of All Buttons (GUI):
- **Load CSV / Generate Sample:** Load real log data or create synthetic data for testing.  
- **Recompute Aggregates / Compute Enriched:** Re-aggregate events and compute behavioral features for analysis.  
- **Run Event Processor:** Execute rule-based risk scoring and generate incident entries.  
- **Run Isolation Forest:** Perform unsupervised anomaly detection and list anomalous users.  
- **Train LSTM:** Train the temporal model with a user-defined lookback window for predictive analysis.  
- **Predict Insider Risk:** Use the trained model to classify users and flag predicted high-risk behavior.  
- **Show Risk Chart / Show Risk Table:** Visualize risk distribution and inspect per-user scores.  
- **Show MITRE Heatmap:** View mapping of detected events to MITRE ATT&CK tactics/techniques.  
- **Export (CSV/HTML):** Export risk tables, anomaly reports, and incidents for documentation or sharing.  
- **Clear Data:** Reset the application state and remove loaded data and model outputs.

---

### Conclusion:
INSIDEO demonstrates a practical approach to insider threat detection by integrating behavioral analytics, rule-based scoring, and machine learning within a single, user-friendly platform. The modular architecture supports easy extension of detection capabilities and reproducible builds via the included PyInstaller spec file. By separating source code from compiled binaries (distributed through Releases) and providing clear visualization and export functions, the project is suitable for academic evaluation, SOC-style demonstrations, and further development toward enterprise readiness. Future enhancements can include real-time log ingestion, additional detection models, and integration with SIEM/DLP tooling.
<p align="center">
  <img 
    src="https://github.com/user-attachments/assets/40f80650-1682-4922-b583-4aa36030d6c6" alt="Demo GIF" style="max-width: 100%; height: auto;"/>
</p>






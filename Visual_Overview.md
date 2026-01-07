# Visual Overview — INSIDEO - Insider Threat Predictor System

This document provides a visual walkthrough of the INSIDEO – Insider Threat Predictor system.  
It explains the logical flow, architectural diagrams, and graphical user interface (GUI) screens used throughout the project.  
Each section is aligned with the system workflow to help reviewers, evaluators, and users understand how the application operates from data ingestion to insider threat prediction.

---

## 1. System Flow Overview

### Flow Chart

The flow chart illustrates the end-to-end execution pipeline of the Insider Threat Predictor system. It begins with loading or generating user activity logs, followed by aggregation and behavioral feature extraction. The processed data is then evaluated using rule-based risk scoring and anomaly detection techniques. Finally, the system visualizes results and allows exporting of reports for further analysis.

<img width="2346" height="717" alt="image" src="https://github.com/user-attachments/assets/1e936748-3e4c-4363-9f35-9082a5e1b5cb" />

## 2. UML Diagrams

### Use Case Diagram

The use case diagram represents the interaction between the analyst and the system. It highlights core functionalities such as loading logs, computing aggregates, running predictions, performing anomaly detection, training models, and exporting reports. This diagram provides a high-level view of system capabilities from a user perspective.

<img width="1394" height="838" alt="image" src="https://github.com/user-attachments/assets/1a621772-3fdc-4152-a4ba-ddfc719a744e" />

## 3. Class Diagram

The class diagram depicts the internal structure of the system, including data processing modules, machine learning components, visualization handlers, and GUI controllers. It shows how different classes interact to support aggregation, risk scoring, anomaly detection, and prediction workflows.

<img width="1856" height="1004" alt="image" src="https://github.com/user-attachments/assets/d3327519-5075-48b3-860f-af68b7762b26" />

---

## 4. Graphical User Interface Overview

The GUI is designed to simulate a Security Operations Center (SOC) environment, enabling analysts to perform insider threat detection tasks through an interactive and structured interface.

---

### Executable Application (.EXE)

This screen represents the packaged Windows executable generated using PyInstaller. The executable allows the system to run independently without requiring a Python environment, making deployment and demonstration easier.

<img width="846" height="858" alt="image" src="https://github.com/user-attachments/assets/3d633cfe-7f08-45fa-9779-b2dfda3c6611" />

### Main Screen

The main screen serves as the central control panel of the application. It provides navigation to different analysis modules such as aggregates, prediction, anomaly detection, risk scoring, and model training. Status indicators and quick access controls help guide the analysis workflow.

<img width="1993" height="1058" alt="image" src="https://github.com/user-attachments/assets/e16b5387-9d3b-4f20-b888-b6a682041e0d" />

### Instruction Manual Screen

This screen provides built-in guidance for users, explaining how to operate different controls within the system. It ensures usability for first-time users and reduces the learning curve when navigating the application.

<img width="1384" height="1092" alt="image" src="https://github.com/user-attachments/assets/096855c6-b211-4f76-b5a0-b1da2cbe49f2" />

### About Me Screen

The About section displays developer and project-related information. It provides context about the project origin, purpose, and contributor details, enhancing transparency and documentation quality.

<img width="1539" height="1058" alt="image" src="https://github.com/user-attachments/assets/b4cd6e20-59df-4b14-a08e-bef43b92b367" />

## HTML-Based Report View

The system also generates an HTML-based report for enhanced visualization and presentation. This report consolidates risk scores, anomalies, and MITRE ATT&CK mappings into a clean and readable format that can be opened directly in a browser.

<p align="center">
  <img 
    src="https://github.com/user-attachments/assets/02644518-83cb-4215-8785-0ffb31ad6059" alt="INSIDEO Project Overview" style="max-width: 100%; height: auto;"
  />
</p>

##  Analysis Control Panels

### Aggregates Controls

The Aggregates Controls module handles data ingestion and preprocessing. It allows users to load CSV files or generate sample data, compute per-user and per-day aggregates, derive enriched behavioral features, and reset data for fresh analysis cycles.

<img width="1420" height="977" alt="image" src="https://github.com/user-attachments/assets/b0060c41-c7c9-4828-9ec7-4fd74e193f97" />

### Prediction Controls

The Prediction Controls module applies rule-based logic to user events. It computes risk scores using predefined weights, identifies potential security incidents, and displays recent activity summaries for rapid assessment.

<img width="1451" height="991" alt="image" src="https://github.com/user-attachments/assets/af430326-cb96-4e6e-b970-52a945705549" />

### Anomaly Detection Controls

This module executes the Isolation Forest algorithm to identify users whose behavior deviates significantly from established patterns. It highlights anomalous users and provides export functionality for anomaly reports in CSV format.

<img width="1444" height="997" alt="image" src="https://github.com/user-attachments/assets/a1a40249-29e3-4ac0-b942-7ea123f5f54d" />

### Risk Score Controls

The Risk Score Controls module visualizes user risk levels through tables and charts. It also includes a MITRE ATT&CK heatmap to map detected activities to standardized attack techniques, supporting effective threat correlation and prioritization.

<img width="1431" height="980" alt="image" src="https://github.com/user-attachments/assets/08ba6a06-9078-4d5f-984f-df2d97783e9c" />

### Model Train Controls

The Model Train Controls module supports advanced analysis using an LSTM-based model. Users can define a lookback window, train the model on historical behavior sequences, and generate predictions and alerts for high-risk users.

<img width="1431" height="981" alt="image" src="https://github.com/user-attachments/assets/7bdc1a51-a065-41bf-9e18-63183c1a4973" />

## Summary

This visual overview demonstrates how INSIDEO integrates data aggregation, behavioral analysis, machine learning, and visualization within a unified GUI. By combining flow diagrams, UML representations, and real interface screens, the document provides a complete understanding of the system’s operational flow and analytical capabilities.












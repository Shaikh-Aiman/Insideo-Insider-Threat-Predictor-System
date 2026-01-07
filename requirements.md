# Prerequisites
<p align="center">
  <img 
    src="https://github.com/user-attachments/assets/18ec0d28-b321-48a2-951a-e4602d5b3310" alt="Image" style="max-width: 100%; height: auto;"/>
</p>


This document explains the system, software, and library requirements needed to run the **Insideo -Insider Threat Predictor System** application successfully.
<br>
---

## Python Dependency File

The project uses a separate `requirements.txt` file for installing dependencies using `pip`.

__Ensure you have the following Python packages installed:__ <br>

- __threading –__ Enables background execution of time-consuming tasks to keep the GUI responsive.
- __traceback –__ Captures and displays detailed error stack traces for debugging and exception handling.
- __datetime –__ Handles timestamps, event ordering, and time-based log aggregation.
- __tkinter –__ Provides the core framework for building the desktop-based graphical user interface.
- __tkinter.ttk –__ Supplies advanced widgets like tables and styled UI components for better visualization.
- __tkinter.filedialog –__ Allows users to select and load external CSV files through the GUI.
- __tkinter.messagebox –__ Displays alerts, warnings, confirmations, and system status messages.
- __pandas –__ Performs data ingestion, cleaning, aggregation, and feature engineering on log data.
- __numpy –__ Supports numerical operations and efficient array processing for analytics and ML tasks.
- __random –__ Generates synthetic user activity data for simulation and testing purposes.
- __sklearn.ensemble.IsolationForest –__ Detects anomalous user behavior using unsupervised machine learning.
- __sklearn.preprocessing.StandardScaler –__ Normalizes feature values to improve anomaly detection accuracy.
- __webbrowser –__ Opens generated HTML reports directly from the application interface.
- __matplotlib –__ Creates visualizations such as risk charts and behavioral analysis plots.
- __matplotlib.backends.backend_tkagg.FigureCanvasTkAgg –__ Embeds matplotlib plots inside the Tkinter GUI.
- __matplotlib.pyplot –__ Provides a plotting interface for generating charts and graphs.
- __PIL.Image –__ Loads and processes image files used within the application interface.
- __PIL.ImageTk –__ Converts images into a Tkinter-compatible format for GUI display.
- __tensorflow.keras.models.Sequential –__ Defines the sequential architecture of the LSTM model.
- __tensorflow.keras.layers.LSTM –__ Learns temporal patterns from sequential user behavior data.
- __tensorflow.keras.layers.Dense –__ Generates final prediction outputs from the neural network.
- __tensorflow.keras.layers.Dropout –__ Reduces overfitting during LSTM model training.
- __tensorflow.keras.optimizers.Adam –__ Optimizes the LSTM model using adaptive learning rates.
- __sys –__ Handles system-level operations such as execution context and runtime control.
- __os –__ Manages file paths and directory operations across different operating systems.
- __tempfile –__ Creates temporary files and directories for intermediate processing tasks.
- __shutil –__ Performs high-level file and directory operations such as copying and cleanup.

<p align="center">
  <img 
    src="https://github.com/user-attachments/assets/7030ba8a-2d7e-408f-a226-8c4e651fcf21" alt="Types of Insider Threats Explained" style="max-width: 100%; height: auto;"/>
</p>


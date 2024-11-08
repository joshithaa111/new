# Enhanced Network Analysis Tool

![Network Analysis Tool](https://res.cloudinary.com/dkqu2s9gz/image/upload/v1731089485/xy30kl6kshejpkac6hd8.png)

## Overview

The Enhanced Network Analysis Tool is a desktop application that allows you to capture, analyze, and visualize network traffic in real-time.

## Key Features

1. **Real-Time Packet Capture**: Capture and analyze network packets in real-time using the Scapy library.
2. **Detailed Packet Information**: Display detailed information about captured packets, including timestamp, protocol, source/destination IP addresses, ports, and packet size.
3. **Packet Filtering**: Filter packets based on IP addresses, protocols, and packet size to focus on specific network traffic.
4. **Network Statistics**: Gather and display various network statistics, such as protocol distribution, IP connection details, and bandwidth usage over time.
5. **Graphical Visualization**: Visualize network statistics using interactive graphs, including a protocol distribution pie chart and a bandwidth usage line chart.
6. **Persistent Data Storage**: Store captured packet data in a SQLite database for later analysis and reporting.
7. **Reporting**: Generate comprehensive network analysis reports that summarize key findings and statistics.

## Prerequisites

To run the Enhanced Network Analysis Tool, you will need the following:

1. **Python 3.x**: Ensure you have Python 3.x installed on your system.
2. **Scapy**: The application uses the Scapy library for network packet capture and analysis. Scapy is a powerful Python-based network packet manipulation tool.
3. **Npcap**: The application also requires the Npcap library, which is a Windows Packet Capture (WinPcap) compatible packet capture library for Windows.
4. **Tkinter**: The GUI of the application is built using the Tkinter library, which is a standard GUI library for Python.
5. **SQLite3**: The application uses the SQLite3 library for persistent data storage.
6. **Matplotlib**: The application uses the Matplotlib library for generating the network statistics graphs.

To install the required dependencies, run the following commands:

```
pip install scapy
pip install tkinter
pip install sqlite3
pip install matplotlib
```

For Npcap, you can download the latest version from the official Npcap website: [https://nmap.org/npcap/](https://nmap.org/npcap/). Follow the installation instructions provided on the website.

## Installation and Usage

To use the Enhanced Network Analysis Tool, follow these steps:

1. **Clone the Repository**: Clone the repository to your local machine:
   ```
   git clone https://github.com/kemalcalak/Realtime-Network-Monitor.git
   ```
2. **Install Dependencies**: Navigate to the project directory and install the required dependencies using pip:
   ```
   cd Realtime-Network-Monitor
   pip install -r requirements.txt
   ```
3. **Run the Application**: Start the application by running the `main.py` script:
   ```
   python main.py
   ```
4. **Packet Capture and Analysis**: Use the GUI to start capturing network packets, apply filters, and view the captured data and generated statistics.
5. **Reporting**: Click the "Report" button to generate and view a detailed network analysis report.

## Visualization Errors

According to the information provided in the readme, the application does not initially display the protocol distribution pie chart. However, this chart is visible in the upper part of the statistics section.

This suggests that the initialization or updating of the graphs is not being handled correctly. To provide users with a consistent and complete visual experience, this visualization issue should be addressed.

## License

This project is licensed under the [MIT License](LICENSE).

## Contact

Feel free to reach out for any questions or feedback:

- [kemalcalak.com](https://kemalcalak.com/contact)
# PCAP Analyzer

A comprehensive packet capture (PCAP) analysis tool and web interface designed for cybersecurity investigations and CTF challenges.

## Features

- **Web Interface:** A Flask-based web application (`app.py`) for uploading and viewing PCAP analysis results.
- **Deep Packet Inspection:** Core analysis engine (`analyzer.py`) capable of parsing various network protocols and identifying suspicious activities.
- **DDoS Detection:** Specialized scripts for detecting DDoS patterns (`ddos_check.py`).
- **File Extraction:** Automatically carves out and reconstructs files transferred over the network.
- **Batch Processing:** Utilities to scan and process multiple PCAPs in bulk (`scan_pcaps.py`).

## Installation

1. Ensure you have Python 3 installed.
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Web Interface

Start the local web server:

```bash
python app.py
```
Then open `http://localhost:5001` in your browser. You can upload `.pcap`, `.pcapng`, or `.cap` files and view the analysis results directly in the UI.

### Command Line Tools

You can also use the individual scripts for specific tasks from the command line:

- **Quick Scan:**
  ```bash
  python quick_test.py
  ```
- **Deep Analysis:**
  ```bash
  python deep_check.py
  ```
- **Batch Scanning:**
  ```bash
  python scan_pcaps.py
  ```

## Project Structure

- `analyzer.py` - Core packet analysis logic.
- `app.py` - Flask web application.
- `static/` - HTML, CSS, and JS files for the web interface.
- `ddos_check.py` / `deep_check.py` - Specialized analysis scripts.
- `requirements.txt` - Python dependencies.

# 🛡️ Anti-Hacking Tool

A Python-based cybersecurity tool that detects cyber attacks by analyzing security log files using the **Berlekamp-Massey algorithm** for pattern recognition and anomaly detection.

Developed as part of a Master's dissertation in Cybersecurity — Aurel Vlaicu University, Arad (2025).


## 🔍 What it does

- Parses and analyzes security log files for suspicious patterns
- Applies the Berlekamp-Massey algorithm to detect anomalies in event sequences
- Flags potential cyber attack signatures from log data
- Outputs detection results with timestamps and severity indicators

## 🚀 Quick Start

### Run locally

```bash
# Clone the repository
git clone https://github.com/geo787/Berlekamp-Massey.git
cd Berlekamp-Massey

# Install dependencies
pip install -r requirements.txt

# Run the detector
python berlekamp_massey_detector.py --log cyber_attack_detection_20250506_151116.log
```

### Run with Docker

```bash
# Build the image
docker build -t anti-hacking-tool.

# Run against a log file
docker run --rm -v $(pwd)/logs:/app/logs anti-hacking-tool --log /app/logs/your_log_file.log
```

## 🗂️ Project Structure

```
├── berlekamp_massey.py          # Core algorithm implementation
├── berlekamp_massey_detector.py # Main detection engine
├── app_security.log             # Sample security log
├── cyber_attack_detection_*.log # Attack detection output logs
├── requirements.txt             # Python dependencies
└── Dockerfile                   # Container configuration
```
## 🧠 Algorithm

The **Berlekamp-Massey algorithm** is used to find the shortest linear feedback shift register (LFSR) that generates a given binary sequence. In this context, it is applied to identify repeating or predictable attack patterns within security logs — flagging deviations that indicate malicious activity.

## 🛠️ Tech Stack

- **Python 3.x**
- Log parsing & pattern analysis
- Docker (containerized deployment)

## 👩‍💻 Author: Roberta Barba — Cybersecurity Analyst & Python Engineer
LinkedIn · GitHub

**Roberta Barba** — Cybersecurity Analyst & Python Engineer  
[LinkedIn](https://linkedin.com/in/roberta-barba-5b99261b5) · [GitHub](https://github.com/geo787)

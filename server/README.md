# Flask Server on GCP

A lightweight Flask application designed to serve a static HTML page and capture credentials via a POST request.

## Installation

Install the required packages:

```bash
pip3 install flask gunicorn
```

Usage:

```bash
gunicorn --bind 0.0.0.0:8080 server:app
```

Access:

```bash
Navigate to: http://34.28.24.97
```
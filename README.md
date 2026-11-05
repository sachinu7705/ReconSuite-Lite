# ReconSuite Lite

A local Linux-based reconnaissance and security assessment dashboard built with Flask and Electron.

## Features
- Subdomain reconnaissance
- Port scanning and scan history
- DNS and WHOIS lookup
- Web discovery and security-header checks
- Vulnerability assessment
- PDF report export
- Local AI assistance using Ollama
- Electron desktop application
- Browser-based dashboard
- Local SQLite storage

## Requirements
- Linux
- Python 3
- Node.js and npm (for development)
- Python dependencies listed in backend/requirements.txt
- Ollama (optional)

## Development Setup

Clone the repository:

    git clone YOUR_GITHUB_REPOSITORY_URL
    cd my-linux-app

Create a virtual environment:

    python3 -m venv .venv
    source .venv/bin/activate

Install dependencies:

    pip install -r backend/requirements.txt
    npm install

Start the application:

    npm start

## Backend

The Flask backend runs locally at http://127.0.0.1:8765.

## Local AI

Ollama API: http://127.0.0.1:11434/v1

Default model: qwen2.5-coder:1.5b

Ollama is optional.

## Data and Privacy

Application databases are stored in ~/.local/share/reconsuite-lite/.
Reports are stored in the configured reports directory.
The backend listens on localhost.

## Responsible Use

Use this application only on systems and networks you own or have explicit permission to assess.

## License

MIT License. See the LICENSE file.

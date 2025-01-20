# Email Cleaner - A Gmail API Project

## Description
A Python-based application to help remove old unwanted clutter from your gmail account.
**WARNING**: This application will delete emails. Proceed with caution.

## Setup
1. Clone the repository
2. Install dependencies:
```
pip install -r requirements.txt
```

### Dependencies
- google-api-python-client
- google-auth-oauthlib

## Usage
Run the main script:
```
python main.py
```

To stop the script while it's running, press `Ctrl+C` (or `Command+C` on macOS) in the terminal. This will safely interrupt the execution.

## Configuration
Ensure `credentials.json` is properly configured before running the application. This file contains the Gmail API credientials from Google, which can be configured and downloaded at https://developers.google.com/gmail.

## License
MIT License
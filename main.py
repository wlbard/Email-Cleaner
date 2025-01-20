from flask import Flask, render_template, redirect, url_for, flash, request, Response, session
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
import os
import json
from queue import Queue
import threading
from datetime import datetime, timedelta, UTC
import base64
import time
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env file

# OAuth2 Configuration
CLIENT_SECRETS_FILE = os.getenv('GOOGLE_OAUTH_CREDENTIALS_PATH')
SCOPES = ['https://mail.google.com/','https://www.googleapis.com/auth/gmail.modify']

# Only enable insecure transport in development
if os.getenv('FLASK_ENV') == 'development':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')

# Create a message queue for SSE updates
message_queue = Queue()

def credentials_to_dict(credentials):
    """Convert credentials to dictionary"""
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

def get_service():
    """Get Gmail service with proper authentication"""
    if 'credentials' not in session:
        return redirect('/authorize')

    credentials = Credentials(**session['credentials'])

    if not credentials or not credentials.valid:
        if credentials and credentials.expired and credentials.refresh_token:
            credentials.refresh(Request())
            session['credentials'] = credentials_to_dict(credentials)
    
    service = build('gmail', 'v1', credentials=credentials)
    return service

@app.route('/')
def index():
    """Home page with email cleanup options."""
    if 'credentials' not in session:
        return redirect('/authorize')
    return render_template('index.html')

@app.route('/authorize')
def authorize():
    """OAuth2 authorization initiation"""
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, 
        scopes=SCOPES,
        redirect_uri=request.base_url.replace('/authorize', '/oauth2callback')
    )
    
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )
    
    session['state'] = state
    return redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    """OAuth2 callback handling"""
    state = session['state']
    
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, 
        scopes=SCOPES,
        state=state,
        redirect_uri=request.base_url
    )
    
    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)
    
    credentials = flow.credentials
    session['credentials'] = credentials_to_dict(credentials)
    
    return redirect('/')

@app.route('/logout')
def logout():
    """Clear the session and logout"""
    if 'credentials' in session:
        del session['credentials']
    return redirect('/')

@app.route('/preview')
def preview():
    """Preview emails before deletion"""
    try:
        if 'credentials' not in session:
            return redirect('/authorize')
            
        category = request.args.get('category', 'all')
        days = int(request.args.get('days', 30))
        
        service = get_service()
        if category == 'all':
            categories = ['promotions', 'social', 'updates', 'forums']
        else:
            categories = [category]
            
        emails = list_emails(service, categories=categories, days=days)
        return render_template('preview.html', emails=emails, days=days)
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
        return redirect('/')

def list_and_delete_old_emails(service, categories="promotions", days=30):
    """
    List and delete emails older than set amount of days.
    Default query clears all promotional emails older than 30 days.
    """
    for cat in categories:
        # 30 days ago from now
        days_ago = (datetime.now() - timedelta(days=days)).isoformat() + 'Z'
        query = f'older_than:{days}d category:{cat}'
        
        while True:
            # Search for promotional emails older than 30 days
            results = service.users().messages().list(userId='me', q=query).execute()
            messages = results.get('messages', [])

            if not messages:
                print(f'No {cat} emails found to delete.')
                break

            print(f"Found {len(messages)} {cat} emails to potentially delete.")
            ids_to_delete = []

            # Loop through all messages found
            for message in messages:
                msg = service.users().messages().get(userId='me', id=message['id']).execute()
                header = service.users().messages().get(userId="me", id=message["id"], format='metadata', metadataHeaders=['Subject', 'From']).execute()
                try:
                    sender = header['payload']['headers'][0]['value']
                    subject = header['payload']['headers'][1]['value']
                except:
                    print(header)
                
                # Check if the email is indeed older than 30 days by checking its internal date
                if int(msg['internalDate']) / 1000 < datetime.strptime(days_ago, '%Y-%m-%dT%H:%M:%S.%fZ').timestamp():
                    print(f'{sender} - {subject}')
                    ids_to_delete.append(message['id'])

            if ids_to_delete:
                # print(ids_to_delete)
                # Batch delete messages
                service.users().messages().batchDelete(userId='me', body={
                    'ids': ids_to_delete
                }).execute()
                print(f"Deleted {len(ids_to_delete)} old {cat} emails.")
            else:
                print("No emails met the criteria for deletion.")

@app.route('/cleanup/<category>/<int:days>')
def cleanup(category, days):
    """Handle email cleanup request."""
    try:
        service = get_service()
        list_and_delete_old_emails(service, categories=[category], days=days)
        flash(f'Successfully cleaned up {category} emails older than {days} days', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
    return redirect(url_for('index'))

def list_emails(service, categories=None, days=30):
    """List emails without deleting them"""
    all_messages = []
    for category in categories:
        send_update(f"Finding {category} emails older than {days} days...")
        
        # Calculate the date for the query
        days_ago = (datetime.now() - timedelta(days=days)).strftime('%Y/%m/%d')
        query = f"category:{category} before:{days_ago}"

        try:
            response = service.users().messages().list(userId='me', q=query).execute()
            messages = response.get('messages', [])
            
            if not messages:
                send_update(f"No {category} emails found.")
                continue

            send_update(f"Found {len(messages)} {category} emails.")
            
            # Get details for each message
            for message in messages:
                msg_id = message['id']
                msg_data = service.users().messages().get(
                    userId='me', 
                    id=msg_id, 
                    format='metadata',
                    metadataHeaders=['subject', 'from', 'date']
                ).execute()
                
                headers = msg_data['payload']['headers']
                subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), 'No subject')
                sender = next((h['value'] for h in headers if h['name'].lower() == 'from'), 'Unknown sender')
                date = next((h['value'] for h in headers if h['name'].lower() == 'date'), '')
                
                # Convert internal date to readable format
                internal_date = datetime.fromtimestamp(int(msg_data['internalDate'])/1000)
                formatted_date = internal_date.strftime('%Y-%m-%d %H:%M:%S')
                
                all_messages.append({
                    'id': msg_id,
                    'subject': subject,
                    'sender': sender,
                    'date': formatted_date,
                    'category': category
                })
                
                # Add a small delay to prevent rate limiting
                time.sleep(0.1)
                
        except Exception as e:
            send_update(f"Error processing {category}: {str(e)}", 'error')
            raise
            
    return all_messages

def send_update(message, category='info'):
    """Send an update to the web interface"""
    message_queue.put({
        'message': message,
        'category': category
    })

@app.route('/delete-selected', methods=['POST'])
def delete_selected():
    """Delete selected emails"""
    try:
        if 'credentials' not in session:
            return redirect('/authorize')
            
        service = get_service()
        email_ids = request.form.getlist('email_ids')
        
        if not email_ids:
            flash('No emails selected for deletion', 'error')
            return redirect('/')
            
        send_update(f"Starting deletion of {len(email_ids)} selected emails...")
        
        for idx, email_id in enumerate(email_ids, 1):
            try:
                service.users().messages().trash(userId='me', id=email_id).execute()
                send_update(f"Deleted email {idx}/{len(email_ids)}")
                time.sleep(0.1)  # Prevent rate limiting
            except Exception as e:
                send_update(f"Error deleting email {email_id}: {str(e)}", 'error')
                
        send_update(f"Completed deletion of selected emails", 'success')
        flash('Successfully deleted selected emails', 'success')
        
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
        
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True, port=8080)

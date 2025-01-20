from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import pickle
import os.path
from datetime import datetime, timedelta, UTC
import base64
import time

# If modifying these scopes, delete the file token.pickle.
SCOPES = ['https://mail.google.com/','https://www.googleapis.com/auth/gmail.modify']

def get_service():
    """
    Set up authentication and return Gmail API service object.
    """
    creds = None
    # The file token.pickle stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first time.
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)

    return build('gmail', 'v1', credentials=creds)

def list_and_delete_old_emails(service, categories="promotions", days=30):
    """
    List and delete emails older than set amount of days.
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

if __name__ == '__main__':
    service = get_service()
    list_and_delete_old_emails(service, categories=["social", "promotions", "forums"], days=365*5)

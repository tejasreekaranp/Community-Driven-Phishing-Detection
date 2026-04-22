import gspread
from google.oauth2.service_account import Credentials
from datetime import datetime

SCOPES = [
    'https://www.googleapis.com/auth/spreadsheets',
    'https://www.googleapis.com/auth/drive'
]

def get_sheet():
    creds = Credentials.from_service_account_file(
        'credentials.json', scopes=SCOPES
    )
    client = gspread.authorize(creds)
    sheet = client.open("Phishing Community Reports").sheet1
    return sheet

def log_report(url, status, note=""):
    try:
        sheet = get_sheet()
        sheet.append_row([
            datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            url,
            status,
            note
        ])
        return True
    except Exception as e:
        print("Sheets error:", e)
        return False

def get_report_count(url):
    try:
        sheet = get_sheet()
        records = sheet.get_all_values()
        count = sum(1 for row in records[1:] if len(row) > 1 and row[1] == url)
        return count
    except Exception as e:
        print("Sheets error:", e)
        return 0
import requests
import time
import urllib3
import zipfile
import os
import smtplib
import logging
import adaptive_card as nessus_adaptive_card
from logging.handlers import RotatingFileHandler
from datetime import datetime
from dotenv import load_dotenv
from email.message import EmailMessage

# === Load environment variables ===
load_dotenv()

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# === Logging settings ===
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)
log_file = os.path.join(LOG_DIR, "nessus_report.log")

handler = RotatingFileHandler(
    log_file, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8"
)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[handler, logging.StreamHandler()],
)

# === Nessus related parameters ===
NESSUS_URL = os.getenv("NESSUS_URL")
ACCESS_KEY = os.getenv("ACCESS_KEY")
SECRET_KEY = os.getenv("SECRET_KEY")
PH_FOLDER_ID = int(os.getenv("PH_FOLDER_ID"))
TP_FOLDER_ID = int(os.getenv("TP_FOLDER_ID"))
OUTPUT_DIR = os.getenv("OUTPUT_DIR")

# === Email settings ===
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT"))
MAIL_TO = os.getenv("EMAIL_TO").split(",")
MAIL_FROM = os.getenv("EMAIL_FROM")
MAIL_SUBJECT = os.getenv("EMAIL_SUBJECT")

# === Teams Webhook ===
TEAMS_WEBHOOK_URL = os.getenv("TEAMS_WEBHOOK_URL")

# === API Header ===
headers = {
    "X-ApiKeys": f"accessKey={ACCESS_KEY}; secretKey={SECRET_KEY}",
    "Content-type": "application/json",
}


def send_teams_message(message: str, message_type: str = "info"):
    """使用 Teams Webhook 發送訊息"""
    if not TEAMS_WEBHOOK_URL:
        logging.warning("⚠️ TEAMS_WEBHOOK_URL is not set, unable to send Teams notifications.")
        return
    payload = nessus_adaptive_card.Adaptive_Card_Notification(
        body=[
            {
                "type": "TextBlock",
                "text": message,
                "wrap": True,
                "weight": "Bolder",
                "size": "medium",
                "color": message_type,
                "separator": True,
            }
        ],
        time=datetime.now().strftime("%Y-%m"),
    )
    try:
        resp = requests.post(TEAMS_WEBHOOK_URL, json=payload)
        if resp.status_code == 202:
            logging.info("📩 Teams notification has been sent.")
        else:
            logging.error(f"❌ Teams notification failed：{resp.status_code} {resp.text}")
    except Exception as e:
        logging.error(f"❌ Teams notification sending exception：{e}")


def get_scans_in_folder(folder_id):
    logging.info(f"Starting to fetch Folder ID: {folder_id} scanning task...")
    resp = requests.get(f"{NESSUS_URL}/scans", headers=headers, verify=False)
    resp.raise_for_status()
    scans = [
        scan for scan in resp.json().get("scans", []) if scan["folder_id"] == folder_id
    ]
    logging.info(f"Found {len(scans)} scanning tasks.")
    return scans


def export_report_to_memory(
    scan_id, scan_name, chapters, fmt="html", suffix="", month_str=""
):
    try:
        export_url = f"{NESSUS_URL}/scans/{scan_id}/export"
        data = {"format": fmt, "chapters": chapters}
        resp = requests.post(export_url, headers=headers, json=data, verify=False)
        resp.raise_for_status()
        file_id = resp.json()["file"]

        status_url = f"{NESSUS_URL}/scans/{scan_id}/export/{file_id}/status"
        while True:
            status_resp = requests.get(status_url, headers=headers, verify=False)
            status_resp.raise_for_status()
            if status_resp.json()["status"] == "ready":
                break
            time.sleep(2)

        download_url = f"{NESSUS_URL}/scans/{scan_id}/export/{file_id}/download"
        report_resp = requests.get(download_url, headers=headers, verify=False)
        report_resp.raise_for_status()

        safe_name = scan_name.replace("/", "_").replace("\\", "_")
        filename = f"{safe_name}_{month_str}_{suffix}_report.html"
        logging.info(f"✅ {filename} export successful.")
        return filename, report_resp.content

    except Exception as e:
        logging.error(f"❌ Export report failed：{scan_name} ({e})")
        return None, None


def send_email_with_attachment(subject, body, to_emails, attachment_path, folder_name):
    try:
        msg = EmailMessage()
        msg["From"] = MAIL_FROM
        msg["To"] = ", ".join(to_emails)
        msg["Subject"] = subject
        msg.set_content(body)

        with open(attachment_path, "rb") as f:
            data = f.read()
            msg.add_attachment(
                data,
                maintype="application",
                subtype="zip",
                filename=os.path.basename(attachment_path),
            )

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.send_message(msg=msg)

        logging.info(
            f"📧 Email sent successfully → {to_emails}（Attachment：{os.path.basename(attachment_path)}）"
        )
        send_teams_message(
            f"✅ {subject} Email has been sent to {to_emails}（Attachment：{os.path.basename(attachment_path)}）",
            message_type="good",
        )

    except Exception as e:
        logging.error(f"❌ {folder_name} Email sending failed：{e}")
        send_teams_message(
            f"❌ {folder_name} Email sending failed：{e}", message_type="attention"
        )


def process_folder_and_send_email(folder_id, folder_name, month_str):
    try:
        logging.info(f"========== Processing folder: {folder_name} ==========")
        scans = get_scans_in_folder(folder_id)
        if not scans:
            logging.warning(f"⚠️ [{folder_name}] No scanning tasks found, skipping.")
            send_teams_message(
                f"⚠️ [{folder_name}] No scanning tasks found, skipping this month's Nessus report.",
                message_type="warning",
            )
            return
        if not os.path.exists(OUTPUT_DIR):
            os.makedirs(OUTPUT_DIR)

        zip_filename = os.path.join(
            OUTPUT_DIR, f"nessus_reports_{folder_name}_{month_str}.zip"
        )

        with zipfile.ZipFile(zip_filename, "w", zipfile.ZIP_DEFLATED) as zipf:
            for scan in scans:
                fname1, content1 = export_report_to_memory(
                    scan["id"],
                    scan["name"],
                    chapters="exploitable_vulns_top25;exploitable_vulns_by_plugin",
                    suffix="vuln_summary",
                    month_str=month_str,
                )
                if fname1 and content1:
                    zipf.writestr(fname1, content1)

                fname2, content2 = export_report_to_memory(
                    scan["id"],
                    scan["name"],
                    chapters="remediations",
                    suffix="remediations",
                    month_str=month_str,
                )
                if fname2 and content2:
                    zipf.writestr(fname2, content2)

        logging.info(f"✅ [{folder_name}] ZIP file has been successfully created.：{zip_filename}")
        send_teams_message(
            f"✅ [{folder_name}] Nessus report for this month has been successfully packaged：{os.path.basename(zip_filename)}",
            message_type="good",
        )

        body = f"Hi,\nThis is {folder_name} ({month_str}) Nessus scan report. \nPlease refer to the attached ZIP file.\n\n— Automated Reporting System"
        subject = f"{MAIL_SUBJECT} - {folder_name} - {month_str}"

        send_email_with_attachment(subject, body, MAIL_TO, zip_filename, folder_name)

    except Exception as e:
        logging.error(f"❌ [{folder_name}] Processing failed：{e}")
        send_teams_message(
            f"❌ [{folder_name}] Nessus report processing failed：{e}",
            message_type="attention",
        )


if __name__ == "__main__":
    month_str = datetime.now().strftime("%Y%m")

    logging.info("🚀 Starting Nessus report automation process")
    process_folder_and_send_email(PH_FOLDER_ID, "PH", month_str)
    process_folder_and_send_email(TP_FOLDER_ID, "TP", month_str)
    logging.info("🎉 All folder report processing completed\n")
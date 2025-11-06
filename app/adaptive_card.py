def Adaptive_Card_Notification(body: dict, time: str):
    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": "null",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {
                            "type": "TextBlock",
                            "text": "🚨 Nessus Scan Report Notification",
                            "wrap": True,
                            "weight": "Bolder",
                            "size": "medium",
                            "color": "info",
                            "separator": False,
                        },
                        {
                            "type": "TextBlock",
                            "text": "📅 " + time,
                            "wrap": True,
                            "weight": "Bolder",
                            "size": "medium",
                            "color": "info",
                            "separator": False,
                        },
                        *body
                    ],
                },
            }
        ],
    }

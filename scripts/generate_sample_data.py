# scripts/generate_sample_data.py
import json
import random
from datetime import datetime, timedelta

def generate_sample_alerts(count=50):
    techniques = ['T1055', 'T1053', 'T1566.001', 'T1082', 'T1003', 'T1027']
    alerts = []
    
    for i in range(count):
        alert = {
            'alert_id': f'ALT-{1000 + i}',
            'timestamp': (datetime.now() - timedelta(hours=random.randint(0, 72))).isoformat(),
            'severity': random.choice(['Low', 'Medium', 'High', 'Critical']),
            'description': f'Suspicious activity detected #{i}',
            'command_line': random.choice([
                'powershell -ep bypass -c "VirtualAllocEx"',
                'schtasks /create /tn "UpdateTask"',
                'mimikatz.exe "privilege::debug"',
                'systeminfo | findstr "OS"'
            ]),
            'process_name': random.choice(['powershell.exe', 'cmd.exe', 'mimikatz.exe', 'unknown.exe']),
            'source_ip': f'192.168.1.{random.randint(1, 254)}',
            'destination_ip': f'10.0.0.{random.randint(1, 254)}'
        }
        alerts.append(alert)
    
    with open('app/data/sample_alerts.json', 'w') as f:
        json.dump(alerts, f, indent=2)
    
    print(f"Generated {count} sample alerts")

if __name__ == '__main__':
    generate_sample_alerts()
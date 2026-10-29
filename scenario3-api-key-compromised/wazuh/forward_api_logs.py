"""Forward new EngineSquare JSON log lines to the local Wazuh Docker manager."""
import json
import subprocess
import time
from pathlib import Path

source = Path(__file__).resolve().parents[2] / 'security_events.jsonl'
if not source.exists():
    raise SystemExit('Start the API server first so security_events.jsonl exists.')
print('Forwarding NEW API log lines to Wazuh. Keep this window open; Ctrl+C stops it.')
with source.open(encoding='utf-8') as stream:
    stream.seek(0, 2)
    try:
        while True:
            position = stream.tell()
            line = stream.readline()
            if not line or not line.endswith('\n'):
                stream.seek(position)
                time.sleep(0.5)
                continue
            event = json.loads(line)
            if event.get('target_resource') not in ('/api/data', '/automation/revoke-key'):
                continue
            subprocess.run(['docker', 'exec', '-i', 'wazuh-manager', 'sh', '-c',
                            'cat >> /var/ossec/logs/enginesquare-scenario3.jsonl'],
                           input=line.encode('utf-8'), check=True)
            print(event.get('timestamp'), event.get('event_type'), event.get('client_ip'))
    except KeyboardInterrupt:
        print('Stopped.')

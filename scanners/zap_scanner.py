import time
from zapv2 import ZAPv2

class ZAPScanner:
    def __init__(self, zap_api_key=None, zap_proxy='http://localhost:8080'):
        self.zap = ZAPv2(apikey=zap_api_key, proxies={'http': zap_proxy, 'https': zap_proxy})
    
    def scan(self, target_url):
        try:
            # Start spidering the target
            print(f"[ZAP] Spidering target {target_url}")
            scan_id = self.zap.spider.scan(target_url)
            
            # Poll until spider completes
            while int(self.zap.spider.status(scan_id)) < 100:
                print(f"[ZAP] Spider progress: {self.zap.spider.status(scan_id)}%")
                time.sleep(5)
            
            # Wait for passive scanning to complete
            print("[ZAP] Waiting for passive scanning...")
            time.sleep(5)
            
            # Start active scanning
            print(f"[ZAP] Starting active scan for {target_url}")
            ascan_id = self.zap.ascan.scan(target_url)
            
            # Poll until active scan completes
            while int(self.zap.ascan.status(ascan_id)) < 100:
                print(f"[ZAP] Active scan progress: {self.zap.ascan.status(ascan_id)}%")
                time.sleep(10)
            
            # Get alerts
            alerts = self.zap.core.alerts(baseurl=target_url)
            return self.format_alerts(alerts)
            
        except Exception as e:
            return {"error": str(e)}
    
    def format_alerts(self, alerts):
        formatted = {
            "vulnerabilities": [],
            "summary": {
                "high": 0,
                "medium": 0,
                "low": 0,
                "informational": 0
            }
        }
        
        for alert in alerts:
            risk = alert.get('risk', 'Informational').lower()
            
            # Count by risk level
            if risk == 'high':
                formatted["summary"]["high"] += 1
            elif risk == 'medium':
                formatted["summary"]["medium"] += 1
            elif risk == 'low':
                formatted["summary"]["low"] += 1
            else:
                formatted["summary"]["informational"] += 1
            
            # Add vulnerability details
            formatted["vulnerabilities"].append({
                "name": alert.get('name', 'Unknown'),
                "risk": risk,
                "description": alert.get('description', ''),
                "solution": alert.get('solution', ''),
                "url": alert.get('url', ''),
                "param": alert.get('param', ''),
                "evidence": alert.get('evidence', '')
            })
        
        return formatted
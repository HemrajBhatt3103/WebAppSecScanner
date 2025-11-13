import time
import requests
from zapv2 import ZAPv2

class ZAPScanner:
    def __init__(self, zap_api_key='l4rmtd48i116at4vg64fs7fnce', zap_proxy='http://localhost:8080'):
        self.zap_proxy = zap_proxy
        self.api_key = zap_api_key
        
        # Test the connection with different approaches
        self.zap = self._connect_to_zap()
    
    def _connect_to_zap(self):
        """Try different connection methods to ZAP"""
        connection_methods = [
            # Try with API key first
            lambda: ZAPv2(apikey=self.api_key, proxies={'http': self.zap_proxy, 'https': self.zap_proxy}),
            # Try without API key
            lambda: ZAPv2(proxies={'http': self.zap_proxy, 'https': self.zap_proxy}),
        ]
        
        for method in connection_methods:
            try:
                zap = method()
                # Test the connection
                version = zap.core.version
                print(f"[ZAP] Connected to ZAP version: {version}")
                return zap
            except Exception as e:
                print(f"[ZAP] Connection attempt failed: {e}")
                continue
        
        print(f"[ZAP] Could not connect to ZAP at {self.zap_proxy}")
        print("[ZAP] Please ensure ZAP is running with the API enabled")
        return None
    
    def scan(self, target_url):
        # If ZAP is not available, return error
        if self.zap is None:
            return {
                "error": f"ZAP is not running or not accessible at {self.zap_proxy}.",
                "vulnerabilities": [],
                "summary": {
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "informational": 0
                }
            }
        
        try:
            # Configure ZAP for better performance
            self._configure_zap()
            
            # Start spidering the target
            print(f"[ZAP] Spidering target {target_url}")
            
            try:
                scan_id = self.zap.spider.scan(url=target_url)
            except Exception as e:
                return {
                    "error": f"ZAP spider failed to start: {str(e)}",
                    "vulnerabilities": [],
                    "summary": {
                        "high": 0,
                        "medium": 0,
                        "low": 0,
                        "informational": 0
                    }
                }
            
            # Poll until spider completes with more flexible timeout
            print("[ZAP] Waiting for spider to complete...")
            max_spider_time = 600  # 10 minutes maximum for spider
            poll_interval = 10     # Check every 10 seconds
            start_time = time.time()
            last_progress = 0
            stuck_count = 0
            
            while True:
                try:
                    progress = int(self.zap.spider.status(scan_id))
                    print(f"[ZAP] Spider progress: {progress}%")
                    
                    # Check if we're making progress
                    if progress == last_progress:
                        stuck_count += 1
                    else:
                        stuck_count = 0
                        last_progress = progress
                    
                    # Stop if completed
                    if progress >= 100:
                        print("[ZAP] Spider completed successfully")
                        break
                    
                    # Stop if stuck at same progress for too long (2 minutes)
                    if stuck_count >= 12:  # 12 * 10 seconds = 2 minutes
                        print("[ZAP] Spider seems stuck, proceeding with current results")
                        break
                    
                    # Stop if timeout reached
                    if time.time() - start_time > max_spider_time:
                        print("[ZAP] Spider timeout reached, proceeding with current results")
                        break
                    
                    time.sleep(poll_interval)
                    
                except Exception as e:
                    print(f"[ZAP] Error checking spider status: {e}")
                    break
            
            # Wait for passive scanning to complete
            print("[ZAP] Waiting for passive scanning...")
            time.sleep(15)  # Increased passive scan time
            
            # Get alerts even if spider didn't complete 100%
            print("[ZAP] Collecting scan results...")
            try:
                alerts = self.zap.core.alerts(baseurl=target_url)
                results = self.format_alerts(alerts)
                
                # Add note if spider didn't complete
                if progress < 100:
                    results["summary"]["note"] = f"Spider completed {progress}%. Results may be partial."
                
                return results
                
            except Exception as e:
                return {
                    "error": f"Failed to get alerts from ZAP: {str(e)}",
                    "vulnerabilities": [],
                    "summary": {
                        "high": 0,
                        "medium": 0,
                        "low": 0,
                        "informational": 0,
                        "note": f"Spider completed {progress}% before error"
                    }
                }
            
        except Exception as e:
            return {
                "error": f"ZAP scan failed: {str(e)}",
                "vulnerabilities": [],
                "summary": {
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "informational": 0
                }
            }
    
    def _configure_zap(self):
        """Configure ZAP for better scanning performance"""
        try:
            # Set spider parameters
            self.zap.spider.set_option_max_depth(5)
            self.zap.spider.set_option_thread_count(2)
            self.zap.spider.set_option_request_wait_time(1000)  # 1 second between requests
            
            # Set scanner parameters
            self.zap.ascan.set_option_thread_per_host(2)
            self.zap.ascan.set_option_max_rule_duration_in_mins(1)
            
            print("[ZAP] Configuration applied successfully")
        except Exception as e:
            print(f"[ZAP] Configuration warning: {e}")
    
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


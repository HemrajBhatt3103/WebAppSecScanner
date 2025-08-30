import subprocess
import json

class WhatWebScanner:
    def scan(self, target_url):
        try:
            # Run WhatWeb with JSON output
            result = subprocess.run(
                ['whatweb', '--log-json=-', target_url],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                return self.parse_output(result.stdout)
            else:
                return {"error": result.stderr}
                
        except subprocess.TimeoutExpired:
            return {"error": "WhatWeb scan timed out"}
        except Exception as e:
            return {"error": str(e)}
    
    def parse_output(self, output):
        try:
            # WhatWeb outputs one JSON object per line
            lines = output.strip().split('\n')
            results = []
            
            for line in lines:
                if line:
                    results.append(json.loads(line))
            
            return self.format_results(results)
        except json.JSONDecodeError:
            return {"error": "Failed to parse WhatWeb output"}
    
    def format_results(self, raw_results):
        formatted = {
            "technologies": [],
            "server": None,
            "framework": None,
            "cms": None,
            "languages": []
        }
        
        for result in raw_results:
            # Extract technologies
            plugins = result.get('plugins', {})
            for plugin_name, plugin_data in plugins.items():
                if plugin_name.lower() != 'title':
                    tech = {
                        "name": plugin_name,
                        "confidence": plugin_data.get('confidence', 0),
                        "version": plugin_data.get('version', ''),
                        "categories": plugin_data.get('categories', [])
                    }
                    formatted["technologies"].append(tech)
                    
                    # Categorize specific technologies
                    if any(cat in plugin_name.lower() for cat in ['php', 'python', 'ruby', 'java', 'asp', 'node']):
                        formatted["languages"].append(plugin_name)
                    elif any(cat in plugin_name.lower() for cat in ['wordpress', 'joomla', 'drupal']):
                        formatted["cms"] = plugin_name
                    elif any(cat in plugin_name.lower() for cat in ['apache', 'nginx', 'iis']):
                        formatted["server"] = plugin_name
                    elif any(cat in plugin_name.lower() for cat in ['rails', 'django', 'laravel', 'spring']):
                        formatted["framework"] = plugin_name
        
        return formatted
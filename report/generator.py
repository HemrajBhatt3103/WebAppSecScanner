import json
import os
import time
from jinja2 import Environment, FileSystemLoader

class ReportGenerator:
    def __init__(self):
        self.template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        self.env = Environment(loader=FileSystemLoader(self.template_dir))
    
    def generate_report(self, target, framework_data, vulnerability_data, output_name, format_type):
        # Prepare data for reporting
        report_data = {
            "target": target,
            "scan_date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "frameworks": framework_data,
            "vulnerabilities": self.process_vulnerabilities(vulnerability_data)
        }
        
        if format_type == 'json':
            return self.generate_json_report(report_data, output_name)
        elif format_type == 'html':
            return self.generate_html_report(report_data, output_name)
        elif format_type == 'pdf':
            return self.generate_pdf_report(report_data, output_name)
    
    def process_vulnerabilities(self, vulnerability_data):
        """Process vulnerabilities to prioritize and summarize them"""
        if "error" in vulnerability_data:
            return vulnerability_data
            
        # Sort vulnerabilities by risk level (High > Medium > Low > Informational)
        risk_order = {"high": 0, "medium": 1, "low": 2, "informational": 3}
        vulnerabilities = vulnerability_data.get("vulnerabilities", [])
        
        # Sort by risk level
        vulnerabilities.sort(key=lambda x: risk_order.get(x.get("risk", "informational"), 3))
        
        # Limit the number of vulnerabilities shown (prioritizing higher risk)
        max_vulnerabilities = 15  # Show top 15 most critical vulnerabilities
        if len(vulnerabilities) > max_vulnerabilities:
            # Keep all high and medium risk, limit low and informational
            high_medium = [v for v in vulnerabilities if v.get("risk") in ["high", "medium"]]
            low_info = [v for v in vulnerabilities if v.get("risk") in ["low", "informational"]]
            
            # If we have too many high/medium, limit those too
            if len(high_medium) > max_vulnerabilities:
                vulnerabilities = high_medium[:max_vulnerabilities]
            else:
                # Add some low/informational to fill up to max_vulnerabilities
                vulnerabilities = high_medium + low_info[:max_vulnerabilities - len(high_medium)]
        
        # Truncate long descriptions and solutions
        for vuln in vulnerabilities:
            # Limit description to 200 characters
            if "description" in vuln and len(vuln["description"]) > 200:
                vuln["description"] = vuln["description"][:197] + "..."
            
            # Limit solution to 150 characters
            if "solution" in vuln and len(vuln["solution"]) > 150:
                vuln["solution"] = vuln["solution"][:147] + "..."
        
        # Update the summary counts
        summary = vulnerability_data.get("summary", {})
        filtered_count = len(vulnerabilities)
        total_count = len(vulnerability_data.get("vulnerabilities", []))
        
        if filtered_count < total_count:
            summary["note"] = f"Showing {filtered_count} of {total_count} vulnerabilities. Prioritized by risk level."
        
        return {
            "vulnerabilities": vulnerabilities,
            "summary": summary
        }
    
    def generate_json_report(self, data, output_name):
        filename = f"{output_name}.json"
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        return filename
    
    def generate_html_report(self, data, output_name):
        template = self.env.get_template('report_template.html')
        html_content = template.render(data)
        
        filename = f"{output_name}.html"
        with open(filename, 'w') as f:
            f.write(html_content)
        return filename
    
    def generate_pdf_report(self, data, output_name):
        # Import weasyprint only when needed to avoid early initialization issues
        try:
            from weasyprint import HTML
        except ImportError:
            print("WeasyPrint is not available. Generating HTML report instead.")
            return self.generate_html_report(data, output_name)
        
        # First generate HTML
        html_file = self.generate_html_report(data, "temp_report")
        
        # Convert to PDF
        filename = f"{output_name}.pdf"
        HTML(html_file).write_pdf(filename)
        
        # Remove temporary HTML file
        os.remove(html_file)
        
        return filename
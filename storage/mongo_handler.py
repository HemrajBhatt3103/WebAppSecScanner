from pymongo import MongoClient
from datetime import datetime

class MongoDBHandler:
    def __init__(self, connection_string="mongodb://localhost:27017/", db_name="websecscan"):
        self.client = MongoClient(connection_string)
        self.db = self.client[db_name]
        self.scans_collection = self.db["scans"]
    
    def store_scan(self, target, framework_data, vulnerability_data, report_path):
        scan_record = {
            "target": target,
            "timestamp": datetime.now(),
            "frameworks": framework_data,
            "vulnerabilities": vulnerability_data,
            "report_path": report_path
        }
        
        result = self.scans_collection.insert_one(scan_record)
        return result.inserted_id
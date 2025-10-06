import requests
import os
from dotenv import load_dotenv

load_dotenv()

def check_ip(ip_address):
    """
    Check an IP address against AbuseIPDB API
    
    Args:
        ip_address (str): The IP address to check
        
    Returns:
        dict: Contains abuse confidence score, country, ISP, and last reported date
    """
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    
    if not api_key:
        return {"error": "ABUSEIPDB_API_KEY not found in environment variables"}
    
    url = "https://api.abuseipdb.com/api/v2/check"
    
    headers = {
        "Accept": "application/json",
        "Key": api_key
    }
    
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90,
        "verbose": ""
    }
    
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        
        data = response.json()
        
        if "data" in data:
            return {
                "abuseConfidenceScore": data["data"].get("abuseConfidenceScore", 0),
                "countryCode": data["data"].get("countryCode", "Unknown"),
                "isp": data["data"].get("isp", "Unknown"),
                "lastReportedAt": data["data"].get("lastReportedAt", "Never")
            }
        else:
            return {"error": "Invalid response format from AbuseIPDB"}
            
    except requests.exceptions.RequestException as e:
        return {"error": f"API request failed: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}

import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

def summarize_threat(threat_data, audience="general", focus="risk"):
    """
    Summarize threat data using OpenAI GPT
    
    Args:
        threat_data (dict): The threat data to summarize
        audience (str): The intended audience for the summary (e.g., 'general', 'technical')
        focus (str): The focus area for the summary (e.g., 'risk', 'mitigation')
        
    Returns:
        str: Plain English summary of the threat
    """
    api_key = os.getenv("OPENAI_API_KEY")
    
    if not api_key:
        return "OpenAI API key not configured. Skipping summary."
    
    try:
        client = OpenAI(api_key=api_key)
        
        prompt = f"""Analyze the following IP threat data and provide a dynamic, context-aware summary:

IP Threat Analysis:
- Abuse Confidence Score: {threat_data.get('abuseConfidenceScore', 'N/A')}%
- Country: {threat_data.get('countryCode', 'Unknown')}
- ISP: {threat_data.get('isp', 'Unknown')}
- Last Reported: {threat_data.get('lastReportedAt', 'Never')}
- Total Reports: {threat_data.get('totalReports', 'N/A')}
- Usage Type: {threat_data.get('usageType', 'Unknown')}

Generate a unique, specific summary that:
1. Assesses the actual risk level based on the confidence score
2. Provides context about the geographic location and ISP
3. Mentions any patterns or notable characteristics
4. Gives actionable recommendations based on the threat level

Audience: {audience}
Focus: {focus}

Make this summary feel personalized and specific to this IP, not generic."""
        
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a cybersecurity analyst. Provide concise, actionable threat summaries."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=150
        )
        
        summary = response.choices[0].message.content
        return summary.strip() if summary else "No summary generated."
        
    except Exception as e:
        return f"Could not generate summary: {str(e)}"

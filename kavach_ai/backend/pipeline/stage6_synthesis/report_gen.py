from typing import List, Dict, Any, Optional
from pydantic import BaseModel
import os
import json
import requests
from dotenv import load_dotenv

# Load env variables from project root
load_dotenv()
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))), '.env'))

try:
    from groq import Groq
except ImportError:
    Groq = None

class KavachForensicReport(BaseModel):
    summary: str
    risk_score: int
    contradiction_label: str
    static_findings: List[str]
    dynamic_findings: List[str]

class CertInIncidentReport(BaseModel):
    incident_id: str
    severity: str
    mitre_attack_tactics: List[str]
    mitre_attack_techniques: List[str]
    indicators_of_compromise: Dict[str, List[str]]
    recommended_mitigations: List[str]

class JointForensicReport(BaseModel):
    forensic: KavachForensicReport
    cert_in: CertInIncidentReport
    mitre_attack_json: Dict[str, Any]

def fallback_generate_report(merged: dict) -> dict:
    return JointForensicReport(
        forensic=KavachForensicReport(
            summary="Fallback generated summary based on merged telemetry.",
            risk_score=merged.get("final_score", 0),
            contradiction_label=merged.get("contradiction_label", "UNKNOWN"),
            static_findings=["Static analysis indicators present"],
            dynamic_findings=["Dynamic behavioral indicators present"]
        ),
        cert_in=CertInIncidentReport(
            incident_id=merged.get("job_id", "UNKNOWN_JOB"),
            severity="HIGH" if merged.get("final_score", 0) > 75 else "LOW",
            mitre_attack_tactics=["TA0043"],
            mitre_attack_techniques=["T1636"],
            indicators_of_compromise={"ips": merged.get("behavioral_fingerprint", {}).get("ips", [])},
            recommended_mitigations=["Uninstall APK", "Monitor network"]
        ),
        mitre_attack_json={
            "tactics": ["TA0043"],
            "techniques": ["T1636"]
        }
    ).model_dump()

def generate_report_groq(merged: dict) -> dict:
    if not Groq or not os.getenv("GROQ_API_KEY"):
        return fallback_generate_report(merged)
    
    client = Groq(api_key=os.getenv("GROQ_API_KEY"))
    schema_str = json.dumps(JointForensicReport.model_json_schema(), indent=2)
    prompt = (
        f"You are a malware forensic analyst. Analyze the following malware telemetry data and generate a JSON "
        f"matching this JSON schema:\n{schema_str}\n\n"
        f"Telemetry Data:\n{json.dumps(merged)}"
    )
    try:
        completion = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"}
        )
        content = completion.choices[0].message.content
        # Validate structure matches expected JointForensicReport
        report = JointForensicReport.model_validate_json(content)
        return report.model_dump()
    except Exception as e:
        print(f"Groq generation failed: {e}")
        return fallback_generate_report(merged)

def generate_report_ollama(merged: dict) -> dict:
    schema_str = json.dumps(JointForensicReport.model_json_schema(), indent=2)
    prompt = (
        f"You are a malware forensic analyst. Analyze the following malware telemetry data and generate a JSON "
        f"matching this JSON schema:\n{schema_str}\n\n"
        f"Telemetry Data:\n{json.dumps(merged)}"
    )
    try:
        response = requests.post(
            "http://localhost:11434/api/chat",
            json={
                "model": "llama3",
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
                "format": "json"
            },
            timeout=30
        )
        response.raise_for_status()
        content = response.json()["message"]["content"]
        # Validate structure matches expected JointForensicReport
        report = JointForensicReport.model_validate_json(content)
        return report.model_dump()
    except Exception as e:
        print(f"Ollama generation failed: {e}")
        return fallback_generate_report(merged)

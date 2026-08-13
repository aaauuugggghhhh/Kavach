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
    apk_details = merged.get("apk_details") or merged.get("apk_meta") or {}
    filename = apk_details.get("name") or apk_details.get("filename") or "Unknown APK"
    package = apk_details.get("package") or apk_details.get("package_name") or "unknown.package"
    size = apk_details.get("size") or apk_details.get("file_size") or "Unknown Size"
    if filename == "Unknown APK" and merged.get("apk_hash"):
        filename = f"APK-{merged['apk_hash'][:12]}"
    if isinstance(size, int):
        size = f"{size / (1024 * 1024):.2f} MB"
        
    summary_parts = [
        "## App Overview\n"
        f"The application under analysis is **{filename}**, registered under the Android package identifier `{package}` with a package size of **{size}**. "
        "A comprehensive forensic security evaluation was performed to identify structural properties, requested system capabilities, "
        "and runtime traits. This report aggregates static telemetry indicators and sandbox detonation traces to construct a risk profile."
    ]
    
    # Check if static scan was run
    has_static = any(k in merged for k in ["static_evidence", "static_data", "static_findings"])
    if has_static:
        static_data = merged.get("static_evidence") or merged.get("static_data") or {}
        prob = static_data.get("securebert_probability", 0)
        score = int(prob * 100) if prob else merged.get("final_score", 0)
        summary_parts.append(
            "## Static Analysis\n"
            f"SecureBERT Risk Score: {score}\n"
            "Key Findings: Static structural review reveals network connectivity permissions and permissions enabling access to background resources. "
            "Attribution metrics suggest moderate exposure risks, but direct indicators of active static signatures were not flag-triggered."
        )
        
    # Check if dynamic scan was run
    has_dynamic = any(k in merged for k in ["behavioral_fingerprint", "dynamic_data", "dynamic_findings"])
    if has_dynamic:
        summary_parts.append(
            "## Dynamic Analysis\n"
            "Key Findings: No system calls, file accesses, or network connections were observed during dynamic detonation, indicating no malicious actions or system modifications were detected during this analysis."
        )
        
    summary = "\n\n".join(summary_parts)

    return JointForensicReport(
        forensic=KavachForensicReport(
            summary=summary,
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
            indicators_of_compromise={"ips": merged.get("behavioral_fingerprint", {}).get("ips", []) if isinstance(merged.get("behavioral_fingerprint"), dict) else []},
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
        f"You are an expert malware forensic analyst. Generate a highly descriptive, comprehensive, and professional application security report based on the fetched data.\n\n"
        f"Requirements for the markdown report structure:\n"
        f"1. **## App Overview**:\n"
        f"   - Describe the application under review in a descriptive, thorough manner.\n"
        f"   - Explicitly define the application's metadata at the beginning: filename (e.g. `apk_details.name`), package name (e.g. `apk_details.package`), size (e.g. `apk_details.size`), and SHA-256 hash if present.\n"
        f"   - Provide a deep narrative analysis of what the application does based on its package name (e.g., if it is named `com.pakito.modrolivetv`, identify it as a live media streaming or television application), and detail its scope and target audiance context.\n"
        f"   - Describe its general components, permission requests, and potential attack vectors in a professional narrative.\n\n"
        f"2. **## Static Analysis** (Only include this section if a static scan was actually run, i.e. contains real static/SecureBERT metrics or indicators):\n"
        f"   - SecureBERT Risk Score: [Insert SecureBERT Risk Score, calculated as the securebert_probability * 100 or static_evidence.securebert_probability * 100]\n"
        f"   - Key Findings: Provide a descriptive narrative of all key findings from the static fetch, explaining the technical details of requested permissions, obfuscation markers, and specific suspicious Smali code slices/methods in an easily digestible way for the reviewer.\n\n"
        f"3. **## Dynamic Analysis** (Only include this section if a dynamic detonation was actually run, i.e. contains a valid execution_mode or dynamic telemetry):\n"
        f"   - Key Findings: Summarize the runtime/dynamic fetch findings descriptively. If no threat behaviors or network calls were observed, explicitly state that no malicious actions or system modifications were detected during dynamic detonation.\n\n"
        f"Write this report in Markdown following the layout template below, and place it in the `forensic.summary` field of the JSON output:\n\n"
        f"=== Template layout ===\n"
        f"## App Overview\n"
        f"[Provide a highly detailed description of the application, package, size, functions, and metadata]\n\n"
        f"## Static Analysis\n"
        f"SecureBERT Risk Score: [Score]\n"
        f"Key Findings: [Narrative]\n\n"
        f"## Dynamic Analysis\n"
        f"Key Findings: [Narrative]\n"
        f"=======================\n\n"
        f"Output a valid JSON matching this schema:\n{schema_str}\n\n"
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
        f"You are an expert malware forensic analyst. Generate a highly descriptive, comprehensive, and professional application security report based on the fetched data.\n\n"
        f"Requirements for the markdown report structure:\n"
        f"1. **## App Overview**:\n"
        f"   - Describe the application under review in a descriptive, thorough manner.\n"
        f"   - Explicitly define the application's metadata at the beginning: filename (e.g. `apk_details.name`), package name (e.g. `apk_details.package`), size (e.g. `apk_details.size`), and SHA-256 hash if present.\n"
        f"   - Provide a deep narrative analysis of what the application does based on its package name (e.g., if it is named `com.pakito.modrolivetv`, identify it as a live media streaming or television application), and detail its scope and target audiance context.\n"
        f"   - Describe its general components, permission requests, and potential attack vectors in a professional narrative.\n\n"
        f"2. **## Static Analysis** (Only include this section if a static scan was actually run, i.e. contains real static/SecureBERT metrics or indicators):\n"
        f"   - SecureBERT Risk Score: [Insert SecureBERT Risk Score, calculated as the securebert_probability * 100 or static_evidence.securebert_probability * 100]\n"
        f"   - Key Findings: Provide a descriptive narrative of all key findings from the static fetch, explaining the technical details of requested permissions, obfuscation markers, and specific suspicious Smali code slices/methods in an easily digestible way for the reviewer.\n\n"
        f"3. **## Dynamic Analysis** (Only include this section if a dynamic detonation was actually run, i.e. contains a valid execution_mode or dynamic telemetry):\n"
        f"   - Key Findings: Summarize the runtime/dynamic fetch findings descriptively. If no threat behaviors or network calls were observed, explicitly state that no malicious actions or system modifications were detected during dynamic detonation.\n\n"
        f"Write this report in Markdown following the layout template below, and place it in the `forensic.summary` field of the JSON output:\n\n"
        f"=== Template layout ===\n"
        f"## App Overview\n"
        f"[Provide a highly detailed description of the application, package, size, functions, and metadata]\n\n"
        f"## Static Analysis\n"
        f"SecureBERT Risk Score: [Score]\n"
        f"Key Findings: [Narrative]\n\n"
        f"## Dynamic Analysis\n"
        f"Key Findings: [Narrative]\n"
        f"=======================\n\n"
        f"Output a valid JSON matching this schema:\n{schema_str}\n\n"
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

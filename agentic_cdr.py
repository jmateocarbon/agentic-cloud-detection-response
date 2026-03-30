import time
import sys
import os
import json
import shlex
import subprocess
import glob
import datetime
import re
from google import genai
from google.genai import types
from dotenv import load_dotenv
from google.genai.errors import ServerError

# --- Setup & Configuration ---
load_dotenv()
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

PRIMARY_MODEL = "gemini-flash-lite-latest" 
FALLBACK_MODEL = "gemini-2.5-pro"
REPORTS_DIR = "scan_reports"
PERSONA_DIR = "personas"

FOLDERS = {
    "VULN": "detections/vulnerability",
    "AUDIT": "detections/audit",
    "AGENTIC_OUT": os.path.join(REPORTS_DIR, "agentic_enrichment"),
    "SELF_OUT": os.path.join(REPORTS_DIR, "self_audit")
}

def ensure_dirs():
    """Ensures all ingestion and reporting folders exist."""
    for path in FOLDERS.values():
        os.makedirs(path, exist_ok=True)

def validate_mitre_id(text):
    """Enforces TXXXX regex validation."""
    pattern = r"T\d{4}(?:\.\d{3})?"
    match = re.search(pattern, text)
    return match.group(0) if match else None

def sanitize_payload(data):
    """Recursively sanitizes JSON inputs to prevent prompt injection."""
    if isinstance(data, dict):
        return {k: sanitize_payload(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_payload(i) for i in data]
    elif isinstance(data, str):
        sanitized = data[:1000] 
        injection_keywords = ["ignore previous", "system instruction", "bypass", "you are now", "call tool"]
        for keyword in injection_keywords:
            sanitized = re.sub(keyword, "[REDACTED]", sanitized, flags=re.IGNORECASE)
        return sanitized
    return data

def secure_shell_tool(command_string: str) -> str:
    """Hardened execution with whitelist controls and strict argument validation."""
    try:
        args = shlex.split(command_string)
        
        # 1. Binary Whitelist
        if not args or args[0] not in ["bandit", "semgrep"]: 
            return "Access Denied: Command unauthorized."
        
        # 2. NEW: Argument Injection Defense
        for arg in args[1:]:
            # Block absolute paths, path traversal, and remote config pulling
            if arg.startswith("/") or ".." in arg or arg.startswith("http"):
                print(f"[!] Security Gate Triggered: LLM attempted dangerous argument -> {arg}")
                return f"BLOCKER: Unauthorized argument detected ({arg}). Only local relative paths and default configs are permitted."
        
        result = subprocess.run(args, shell=False, capture_output=True, text=True, timeout=45)
        return result.stdout if result.stdout else result.stderr
    except Exception: 
        print("[!] Shell execution failed.") 
        return "Error: Internal execution failure."

def save_report(content, target_name, is_self_audit=False):
    """Saves reports with path traversal defense."""
    ensure_dirs()
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    sub_dir = FOLDERS["SELF_OUT"] if is_self_audit else FOLDERS["AGENTIC_OUT"]
    
    mitre_id = validate_mitre_id(content)
    uncertain = "MANUAL" in content.upper() or not mitre_id
    prefix = "VERIFIED_" if is_self_audit else ("UNCERTAIN_" if uncertain else "VERIFIED_")
    
    # Path Traversal Defense
    safe_target_name = re.sub(r'[^a-zA-Z0-9_\-]', '_', target_name.replace('.json', ''))
    filename = os.path.join(sub_dir, f"{prefix}{safe_target_name}_{ts}.txt")
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"[+] Report saved: {filename}")

def load_personas():
    """UTF-8 Hardened Persona Loader."""
    personas = {}
    if not os.path.exists(PERSONA_DIR): 
        os.makedirs(PERSONA_DIR)
    for filepath in glob.glob(os.path.join(PERSONA_DIR, "*.md")):
        name = os.path.basename(filepath).replace(".md", "").upper()
        with open(filepath, "r", encoding="utf-8") as f:
            personas[name] = f.read().strip()
    return personas

AGENTS = load_personas()

def call_agent(prompt, role_key, use_shell=False, use_search=False):
    """Executes agent calls with tool configuration and rate limit handling."""
    system_instr = AGENTS.get(role_key, "You are a Security Engineer ingesting security, threat logs and Audit.")
    tools = []
    
    if use_shell:
        tools.append(types.Tool(function_declarations=[{
            "name": "secure_shell_tool",
            "description": "Run SAST scanners (bandit, semgrep).",
            "parameters": {"type": "OBJECT", "properties": {"command_string": {"type": "STRING"}}}
        }]))
    if use_search:
        tools.append(types.Tool(google_search=types.GoogleSearch()))

    config = types.GenerateContentConfig(
        system_instruction=system_instr,
        tools=tools if tools else None,
        automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=False)
    )

    for model in [PRIMARY_MODEL, FALLBACK_MODEL]:
        try:
            chat = client.chats.create(model=model, config=config)
            return chat.send_message(message=prompt)
        except ServerError:
            print(f"[!] Server Error on {model}. Backing off for 2 seconds...")
            time.sleep(2)
        except Exception as e:
            print(f"[!] API error occurred on {model}:{str(e)}")
    return None

def run_self_audit():
    """Performs deterministic SAST scan and Agentic review."""
    print("[*] Performing Pre-flight Self-Audit...")
    print("[-] Running native Bandit scan on core engine...")
    
    try:
        # -lll filters for HIGH severity only to prevent operational downtime
        bandit_result = subprocess.run(
            ["bandit", "-lll", "-r", __file__, "-f", "txt"], 
            capture_output=True, text=True, shell=False
        )
        issues_found = bandit_result.returncode != 0
        scan_output = bandit_result.stdout
    except FileNotFoundError:
        print("[!] FATAL: Bandit is not installed or not in PATH. Run: pip install bandit")
        sys.exit(1)
    except Exception:
        print("[!] FATAL: Failed to execute native SAST scanner. Shutting down.")
        sys.exit(1)

    with open(__file__, 'r', encoding="utf-8") as f:
        source_code = f.read()

    if issues_found:
        prompt = (
            f"A native Bandit scan detected HIGH SEVERITY vulnerabilities in the following script.\n\n"
            f"Bandit Output:\n{scan_output}\n\n"
            f"Source Code:\n{source_code}\n\n"
            f"Analyze the findings. You must ONLY start your response with 'BLOCKER:' if there is a CRITICAL "
            f"Remote Code Execution (RCE) or active Command Injection risk. Ignore minor environmental risks."
        )
    else:
        prompt = f"A native Bandit scan passed cleanly. Briefly review the code for logical flaws:\n\n{source_code}"

    audit_response = call_agent(prompt, "SELF_AUDITOR")
    
    if not audit_response or not hasattr(audit_response, 'text'):
        print("[!] FATAL: Agent D failed to respond. Shutting down.")
        sys.exit(1)

    response_text = audit_response.text
    log_path = os.path.join(FOLDERS.get("SELF_OUT", "scan_reports/self_scan"), "latest_audit_log.txt")
    
    with open(log_path, "w", encoding="utf-8") as log_file:
        log_file.write(f"Bandit Status: {'FAILED' if issues_found else 'PASSED'}\n")
        log_file.write(f"Agent Analysis:\n{response_text}")

    if issues_found and "BLOCKER:" in response_text:
        print("\n[!] SECURITY SHUTDOWN: Pre-flight audit failed.")
        print("-" * 50)
        print(response_text)
        print("-" * 50)
        print(f"[*] Full audit log saved to: {log_path}")
        sys.exit(1)
    elif issues_found and "BLOCKER:" not in response_text:
        print("[+] Pre-flight Audit detected non-critical warnings. Logging and proceeding.")
    else:
        print("[+] Pre-flight Audit Passed. Pipeline secure.\n")

def process_and_verify(data, source_name, role):
    """Specialist -> Verifier pipeline for alert enrichment."""
    print(f"[*] Investigation: {source_name}")
    
    # Apply Prompt Injection Defense
    safe_data = sanitize_payload(data)
    spec_res = call_agent(json.dumps(safe_data), role)
    
    if not spec_res or not hasattr(spec_res, 'text'):
        print(f"[!] Analysis failed for {source_name}")
        return

    # Branch the verification logic based on the specialist persona
    if role == "CVE_EXPERT":
        verify_prompt = (
            f"DATA: {spec_res.text}\n\n"
            "TASK: Find the MITRE TXXXX mapping, the specific Patch Version, and its CISA KEV status. "
            "If you cannot verify the CVE details, start your response with 'STATUS: MANUAL INVESTIGATION REQUIRED'."
        )
    elif role == "CLOUD_ARCHITECT":
        verify_prompt = (
            f"DATA: {spec_res.text}\n\n"
            "TASK: Verify the attack path and find the exact MITRE TXXXX mappings (e.g., Initial Access, Privilege Escalation). "
            "Do NOT look for CVEs, Patch Versions, or CISA KEV status as this is a cloud infrastructure misconfiguration. "
            "If the attack path is logically invalid, start your response with 'STATUS: MANUAL INVESTIGATION REQUIRED'."
        )
    else:
        verify_prompt = f"DATA: {spec_res.text}\n\nTASK: Verify the findings and map to MITRE TXXXX."

    # Call the Verifier with the context-aware prompt
    final_res = call_agent(verify_prompt, "VERIFIER", use_search=True)
    
    if final_res and hasattr(final_res, 'text') and final_res.text:
        save_report(final_res.text.strip(), source_name)

if __name__ == "__main__":
    ensure_dirs()
    print("--- AGENTIC SECURITY POD v3.0 ---")
    run_self_audit()
    
    for f in glob.glob(os.path.join(FOLDERS["VULN"], "*.json")):
        with open(f, 'r', encoding="utf-8") as j:
            process_and_verify(json.load(j).get("data", {}), os.path.basename(f), "CVE_EXPERT")
            
    for f in glob.glob(os.path.join(FOLDERS["AUDIT"], "*.json")):
        with open(f, 'r', encoding="utf-8") as j:
            process_and_verify(json.load(j).get("data", {}), os.path.basename(f), "CLOUD_ARCHITECT")
import sys
import json
from pathlib import Path

# --- Pathing & Import Injection ---
current_dir = Path(__file__).resolve().parent
parent_dir = current_dir.parent
sys.path.insert(0, str(parent_dir))

import agentic_cdr

# --- Test Environment Override ---
agentic_cdr.FOLDERS = {
    "VULN": str(current_dir / "fixtures/vulnerability"),
    "AUDIT": str(current_dir / "fixtures/audit"),
    "AGENTIC_OUT": str(current_dir / "output/agentic_scans"),
    "SELF_OUT": str(current_dir / "output/self_scan")
}

# Monkey Patch: Disable main app's aggressive folder creation
agentic_cdr.ensure_dirs = lambda: None

# --- LLM Evaluation Expectations ---
EXPECTATIONS = {
    "test_hallucination.json": {
        "expected_prefix": "UNCERTAIN_",
        "required_keywords": ["MANUAL INVESTIGATION REQUIRED"]
    },
    "test_cve_expert.json": {
        "expected_prefix": "VERIFIED_",
        "required_keywords": ["CISA", "LOG4J"]
    },
    "test_cloud_architect.json": {
        "expected_prefix": "VERIFIED_",
        "required_keywords": ["T10", "SSH", "STORAGE"]
    }
}

def setup_test_environment():
    """Creates isolated output directories and checks for inputs."""
    Path(agentic_cdr.FOLDERS["AGENTIC_OUT"]).mkdir(parents=True, exist_ok=True)
    Path(agentic_cdr.FOLDERS["SELF_OUT"]).mkdir(parents=True, exist_ok=True)
    
    for input_path in [agentic_cdr.FOLDERS["VULN"], agentic_cdr.FOLDERS["AUDIT"]]:
        if not Path(input_path).exists():
            print(f"[!] Warning: Missing input directory -> {input_path}")

def clean_test_outputs():
    """Wipes the output directories before a run to prevent false positives."""
    for out_dir in [agentic_cdr.FOLDERS["AGENTIC_OUT"], agentic_cdr.FOLDERS["SELF_OUT"]]:
        path = Path(out_dir)
        if path.exists():
            for item in path.glob("*"):
                if item.is_file() and item.name != ".gitkeep":
                    item.unlink()

def validate_test_results(filename: str):
    """Asserts that the AI generated the correct file type and content."""
    if filename not in EXPECTATIONS:
        return 
        
    rules = EXPECTATIONS[filename]
    safe_target_name = filename.replace('.json', '')
    
    out_dir = Path(agentic_cdr.FOLDERS["AGENTIC_OUT"])
    matches = list(out_dir.glob(f"{rules['expected_prefix']}*{safe_target_name}*.txt"))
    
    if not matches:
        print(f"  [FAIL] Expected prefix '{rules['expected_prefix']}' but found none.")
        return
        
    with open(matches[0], "r", encoding="utf-8") as f:
        content = f.read().upper()
        
    for keyword in rules["required_keywords"]:
        if keyword.upper() not in content:
            print(f"  [FAIL] Missing mandatory keyword '{keyword}'.")
            return
            
    print(f"  [PASS] AI reasoning validated successfully.")

def process_test_directory(directory_path: str, persona: str):
    """Loads fixtures, triggers the AI pipeline, and validates the output."""
    json_files = Path(directory_path).glob("*.json")
    
    for file_path in json_files:
        print(f"\n[*] Processing Fixture: {file_path.name}")
        with open(file_path, 'r', encoding="utf-8") as j:
            try:
                data = json.load(j).get("data", {})
                agentic_cdr.process_and_verify(data, file_path.name, persona)
                validate_test_results(file_path.name)
            except json.JSONDecodeError:
                print(f"  [!] WARNING: Invalid JSON format in test fixture.")

def execute_test_suite():
    setup_test_environment()
    print("--- 🧪 RUNNING ISOLATED TEST SUITE ---")
    
    print("\n[-] Cleaning previous test artifacts...")
    clean_test_outputs()
    
    print("\n[-] Testing Pre-flight Integrity (Agent D)...")
    agentic_cdr.run_self_audit()
    
    print("\n[-] Testing Vulnerability Processing (Agents A & C)...")
    process_test_directory(agentic_cdr.FOLDERS["VULN"], "CVE_EXPERT")
            
    print("\n[-] Testing Cloud Audit Processing (Agents B & C)...")
    process_test_directory(agentic_cdr.FOLDERS["AUDIT"], "CLOUD_ARCHITECT")

if __name__ == "__main__":
    execute_test_suite()
    print("\n[+] Test suite complete.")
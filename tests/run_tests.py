import sys
import json
import pytest
from pathlib import Path

# --- Pathing & Import Injection ---
current_dir = Path(__file__).resolve().parent
parent_dir = current_dir.parent
sys.path.insert(0, str(parent_dir))

import agentic_cdr

# --- Test Environment Override ---
# Using a pytest fixture is cleaner for setup/teardown
@pytest.fixture(scope="session", autouse=True)
def setup_test_env():
    # Override folders
    agentic_cdr.FOLDERS = {
        "VULN": str(current_dir / "fixtures/vulnerability"),
        "AUDIT": str(current_dir / "fixtures/audit"),
        "AGENTIC_OUT": str(current_dir / "output/agentic_scans"),
        "SELF_OUT": str(current_dir / "output/self_scan")
    }
    # Monkey Patch
    agentic_cdr.ensure_dirs = lambda: None
    
    # Create dirs
    Path(agentic_cdr.FOLDERS["AGENTIC_OUT"]).mkdir(parents=True, exist_ok=True)
    Path(agentic_cdr.FOLDERS["SELF_OUT"]).mkdir(parents=True, exist_ok=True)
    
    yield # Run tests
    
    # Optional: Clean up after tests
    # clean_test_outputs()

# --- Expectations Logic ---
EXPECTATIONS = {
    "test_hallucination.json": ("UNCERTAIN_", ["MANUAL INVESTIGATION REQUIRED"]),
    "test_cve_expert.json": ("VERIFIED_", ["CISA", "LOG4J"]),
    "test_cloud_architect.json": ("VERIFIED_", ["T10", "SSH", "STORAGE"])
}

# --- The Actual Tests ---

@pytest.mark.unit
def test_preflight_integrity():
    """Verify the Agent D self-audit logic."""
    # If run_self_audit raises an exception, the test fails automatically
    agentic_cdr.run_self_audit()

@pytest.mark.ai
@pytest.mark.parametrize("fixture_file", list((current_dir / "fixtures/vulnerability").glob("*.json")))
def test_vulnerability_processing(fixture_file):
    """Tests Agent A & C against vulnerability fixtures."""
    run_agent_test(fixture_file, "CVE_EXPERT")

@pytest.mark.ai
@pytest.mark.parametrize("fixture_file", list((current_dir / "fixtures/audit").glob("*.json")))
def test_cloud_audit_processing(fixture_file):
    """Tests Agent B & C against cloud audit fixtures."""
    run_agent_test(fixture_file, "CLOUD_ARCHITECT")

def run_agent_test(file_path, persona):
    with open(file_path, 'r', encoding="utf-8") as j:
        data = json.load(j).get("data", {})
    
    # Trigger AI Pipeline
    agentic_cdr.process_and_verify(data, file_path.name, persona)
    
    # Validation
    if file_path.name in EXPECTATIONS:
        prefix, keywords = EXPECTATIONS[file_path.name]
        out_dir = Path(agentic_cdr.FOLDERS["AGENTIC_OUT"])
        safe_name = file_path.name.replace('.json', '')
        matches = list(out_dir.glob(f"{prefix}*{safe_name}*.txt"))
        
        # Proper Assertions: This will cause the exit code 1 if it fails
        assert matches, f"Expected file with prefix {prefix} not found for {file_path.name}"
        
        with open(matches[0], "r", encoding="utf-8") as f:
            content = f.read().upper()
            for kw in keywords:
                assert kw.upper() in content, f"Missing mandatory keyword: {kw}"
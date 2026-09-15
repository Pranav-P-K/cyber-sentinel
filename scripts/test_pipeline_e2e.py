import asyncio
import json
import logging
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.core.pipeline import CyberSentinelPipeline
from frontend.components.alert_input import _multi_attacker_preset

logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(name)s | %(message)s")

async def main():
    print("=== Testing CyberSentinel End-to-End Pipeline ===")
    alerts = _multi_attacker_preset()
    print(f"Loaded {len(alerts)} alerts across 2 attackers (192.168.1.100 and 10.10.50.200)...")
    
    pipeline = CyberSentinelPipeline()
    result = await pipeline.analyze(alerts)
    
    print("\n=== PIPELINE EXECUTION SUCCESSFUL ===")
    print(f"Total Alerts: {result['total_alerts']}")
    print(f"Detected Sessions: {result['session_count']}")
    print(f"Noise Alerts: {result['noise_alerts']}")
    print(f"Processing Time: {result['processing_ms']} ms")
    
    for i, session in enumerate(result['sessions']):
        print(f"\n--- [SESSION {i+1}: {session['session_id'].upper()}] ---")
        print(f"Attacker IPs: {session['attacker_ips']}")
        print(f"Victim IPs:   {session['victim_ips']}")
        print(f"Severity Index (SI): {session['severity_index']:.1f}/100")
        print(f"Kill Chain Velocity (KCV): {session['kcv']:.2f} phases/hr")
        print(f"MITRE Ordered Chain: {session['ordered_chain']}")
        print(f"Chain Labels: {session['chain_labels']}")
        print(f"CGAR HRSS Confidence: {session['hrss']:.3f} (Round 2 triggered: {session['round2_triggered']})")
        print(f"Narrative Preview:\n{session['narrative'][:300]}...")

if __name__ == "__main__":
    asyncio.run(main())

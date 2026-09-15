import json

s_orig = json.load(open("evaluation/ground_truth/s_orig.json", encoding="utf-8"))
s_new  = json.load(open("evaluation/ground_truth/scenarios.json", encoding="utf-8"))

merged = s_orig + s_new

with open("evaluation/ground_truth/scenarios.json", "w", encoding="utf-8") as f:
    json.dump(merged, f, indent=2, ensure_ascii=False)

ids = [s["scenario_id"] for s in merged]
print(f"Total scenarios: {len(merged)}")
print("IDs:", ids)

import os
os.remove("evaluation/ground_truth/s_orig.json")
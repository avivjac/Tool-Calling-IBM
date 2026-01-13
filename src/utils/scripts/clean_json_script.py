import json
import re

with open("Get_an_IP_address_report.txt", "r", encoding="utf-8") as f:
    lines = f.readlines()

with open("output.jsonl", "w", encoding="utf-8") as out:
    for line in lines:
        line = line.strip()
        if not line.startswith("{"):
            continue

        line = re.sub(r",\s*}", "}", line)  # remove trailing commas
        obj = json.loads(line)
        out.write(json.dumps(obj, ensure_ascii=False) + "\n")
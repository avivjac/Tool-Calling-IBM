import re
import json
import sys
from pathlib import Path
from typing import List, Dict, Any, Tuple


# ---------- Helpers ----------
def extract_conversation_blocks(text: str) -> List[str]:
    """
    Extract top-level blocks that start with '[' and end with matching ']'.
    Ignores brackets inside quoted strings (best-effort).
    """
    blocks = []
    start = None
    depth = 0
    in_string = False
    escape = False

    for i, ch in enumerate(text):
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        else:
            if ch == '"':
                in_string = True
                continue

            if ch == "[":
                if depth == 0:
                    start = i
                depth += 1
            elif ch == "]":
                if depth > 0:
                    depth -= 1
                    if depth == 0 and start is not None:
                        blocks.append(text[start : i + 1])
                        start = None

    return blocks


def extract_message_objects(block: str) -> List[str]:
    """
    Given a conversation block "[ {...}, {...} ]", extract each top-level {...} object
    using brace counting that ignores braces inside strings.
    """
    objs = []
    i = 0
    n = len(block)

    # find first '['
    while i < n and block[i] != "[":
        i += 1
    i += 1

    in_string = False
    escape = False
    depth = 0
    start = None

    while i < n:
        ch = block[i]

        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
        else:
            if ch == '"':
                in_string = True
            elif ch == "{":
                if depth == 0:
                    start = i
                depth += 1
            elif ch == "}":
                if depth > 0:
                    depth -= 1
                    if depth == 0 and start is not None:
                        objs.append(block[start : i + 1])
                        start = None

        i += 1

    return objs


def parse_loose_message(obj_text: str) -> Dict[str, Any]:
    """
    Parse a message object even if content contains raw newlines / quotes.
    Strategy:
      - Extract role via regex
      - Extract content as everything between "content": and ,"role": (or end)
      - Clean content: keep raw text, but normalize to a Python string
    """
    # role
    role_m = re.search(r'"role"\s*:\s*"([^"]+)"', obj_text)
    if not role_m:
        raise ValueError("Could not find role in object:\n" + obj_text[:200])
    role = role_m.group(1)

    # content: capture between "content": " .... " and the next ,"role":
    # We do a best-effort capture that supports multiline.
    content_m = re.search(r'"content"\s*:\s*"(.*)"\s*,\s*"role"\s*:', obj_text, flags=re.DOTALL)
    if not content_m:
        # fallback: content last field
        content_m = re.search(r'"content"\s*:\s*"(.*)"\s*}', obj_text, flags=re.DOTALL)
    if not content_m:
        raise ValueError("Could not find content in object:\n" + obj_text[:200])

    raw = content_m.group(1)

    # Unescape common sequences that may already be escaped
    # (But DO NOT try to parse inner JSON; keep as text)
    raw = raw.replace(r"\n", "\n").replace(r"\t", "\t").replace(r"\\", "\\")

    # Important: remove any unescaped CR characters
    raw = raw.replace("\r", "")

    return {"role": role, "content": raw}


def convert(input_path: str, output_path: str) -> Tuple[int, int]:
    text = Path(input_path).read_text(encoding="utf-8", errors="replace")

    conv_blocks = extract_conversation_blocks(text)
    if not conv_blocks:
        raise ValueError("No conversation blocks found (expected '[' ... ']').")

    total_lines = 0
    with Path(output_path).open("w", encoding="utf-8") as out:
        for conv_id, block in enumerate(conv_blocks):
            obj_texts = extract_message_objects(block)

            for msg_text in obj_texts:
                msg = parse_loose_message(msg_text)

                # write each message as one JSON line
                line = {"conversation_id": conv_id, **msg}
                out.write(json.dumps(line, ensure_ascii=False) + "\n")
                total_lines += 1

    return len(conv_blocks), total_lines


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python convert_loose_txt_to_jsonl.py <input.txt> <output.jsonl>")
        sys.exit(1)

    convs, lines = convert(sys.argv[1], sys.argv[2])
    print(f"Done. Conversations: {convs}, JSONL lines written: {lines}")

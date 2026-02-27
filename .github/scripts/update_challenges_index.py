#!/usr/bin/env python3
import re
import yaml
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
ROOT_README = REPO_ROOT / "README.md"
print(f"Repository root: {REPO_ROOT}")

MARKER_START_RE = re.compile(r"<!--\s*CHALLENGES:EVENT=([^:>]+):START\s*-->")
MARKER_END_TEMPLATE = "<!-- CHALLENGES:EVENT={event}:END -->"
EVENT_BLOCK_RE = re.compile(
    r"<!--\s*CHALLENGES:EVENT=([^:>]+):START\s*-->.*?<!--\s*CHALLENGES:EVENT=\1:END\s*-->",
    re.DOTALL,
)

def read_front_matter(md_path: Path):
    text = md_path.read_text(encoding="utf-8")
    if not text.startswith("---"):
        return None, text
    parts = text.split("---", 2)
    if len(parts) < 3:
        return None, text
    _, yaml_part, rest = parts
    meta = yaml.safe_load(yaml_part)
    return meta, rest.lstrip("\n")

def find_event_dirs():
    events = []
    for child in REPO_ROOT.iterdir():
        if child.is_dir() and not child.name.startswith(".") and child.name not in {".github"}:
            events.append(child)
    return events

def collect_challenges():
    events = find_event_dirs()
    result = {}

    for event_dir in events:
        challenges = []
        # every subdir with a README.md is considered a challenge
        for item in event_dir.iterdir():
            if item.is_dir():
                readme = item / "README.md"
                if readme.exists():
                    meta, _ = read_front_matter(readme)
                    if meta:
                        # directory relative to repo root (not the README itself)
                        challenge_dir_rel = item.relative_to(REPO_ROOT).as_posix()
                        challenges.append({
                            "title": meta.get("title", item.name),
                            "date": meta.get("date", ""), # keep for sorting
                            "summary": meta.get("summary", ""),
                            "categories": meta.get("categories", []),
                            "difficulty": meta.get("difficulty", ""),
                            "tags": meta.get("tags", []),
                            "dir": challenge_dir_rel,
                        })
        # sort challenges by date desc (most recent first, blank dates last)
        def sort_key(c):
            return (bool(c["date"]), c["date"] or "")
        challenges.sort(key=sort_key, reverse=True)
        result[event_dir.name] = challenges
    return result

def render_table_for_event(event_name, challenges):
    lines = []
    lines.append(f"<!-- CHALLENGES:EVENT={event_name}:START -->")
    lines.append(f"### {event_name}")
    lines.append("")
    if not challenges:
        lines.append("_No challenges found for this event._")
    else:
        lines.append("| Title | Category | Difficulty | Tags |")
        lines.append("| ----- | -------- | ---------- | ---- |")
        for ch in challenges:
            cats = ", ".join(ch["categories"]) if isinstance(ch["categories"], list) else ch["categories"]
            tags = ", ".join(ch["tags"]) if isinstance(ch["tags"], list) else ch["tags"]
            title_link = f"[{ch['title']}]({ch['dir']})"
            lines.append(
                f"| {title_link} | {cats} | {ch['difficulty']} | {tags} |"
            )
    lines.append(f"<!-- CHALLENGES:EVENT={event_name}:END -->")
    return "\n".join(lines)

def event_latest_date(challenges):
    dated = [ch.get("date") for ch in challenges if ch.get("date")]
    return max(dated) if dated else ""

def sort_events(challenges_by_event):
    ordered = sorted(challenges_by_event.items(), key=lambda item: item[0])
    ordered.sort(key=lambda item: event_latest_date(item[1]), reverse=True)
    return ordered

def update_root_readme(challenges_by_event):
    if not ROOT_README.exists():
        raise SystemExit("Root README.md not found, aborting.")

    original = ROOT_README.read_text(encoding="utf-8")
    ordered_events = sort_events(challenges_by_event)
    rendered_section = "\n\n\n\n".join(
        render_table_for_event(event_name, challenges)
        for event_name, challenges in ordered_events
    )

    block_matches = list(EVENT_BLOCK_RE.finditer(original))
    if block_matches:
        prefix = original[:block_matches[0].start()].rstrip()
        suffix = original[block_matches[-1].end():].strip()
        parts = [p for p in [prefix, rendered_section, suffix] if p]
        updated = "\n\n".join(parts) + "\n"
    else:
        updated = original.rstrip() + "\n\n" + rendered_section + "\n"

    if updated != original:
        ROOT_README.write_text(updated, encoding="utf-8")
        print("README.md updated.")
    else:
        print("README.md is already up to date.")

def main():
    challenges_by_event = collect_challenges()
    update_root_readme(challenges_by_event)

if __name__ == "__main__":
    main()

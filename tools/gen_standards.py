"""Генерирует standards/registry.yaml из таблицы A.1 ТЗ (однократный bootstrap; дальше реестр ведёт владелец, ADR-017)."""
import re, sys, yaml  # noqa: E401

src, dst = sys.argv[1], sys.argv[2]
rows = []
in_a1 = False
for line in open(src, encoding="utf-8"):
    if line.startswith("## A.1"):
        in_a1 = True
    elif line.startswith("## A.2"):
        break
    if not in_a1:
        continue
    if not re.match(r"^\| STD-\d{2} \|", line):
        continue
    cells = [c.strip() for c in line.strip().strip("|").split("|")]
    if len(cells) != 7:
        continue
    code, title, edition, area, evidence, modules, _checked = cells
    mods = re.findall(r"M\d{2}", modules)
    rows.append({
        "standard_id": code,
        "title": title,
        "edition": edition,
        "area": area,
        "required_evidence": evidence,
        "modules": mods,
        "module_refs_raw": modules,
        "applicability": ["enterprise", "saas"] if code != "STD-23" else ["saas"],
        "jurisdictions": ["KZ"] if code == "STD-27" else (["EU"] if code == "STD-28" else ["all"]),
        "owner": "compliance-manager",
        "reviewed_at": None,
        "next_review_at": None,
        "control_mapping_version": "1.0",
    })
doc = {"registry_version": "A-1.0", "as_of": "2026-11-09", "standards": rows}
with open(dst, "w", encoding="utf-8") as f:
    f.write("# Приложение A — Standards Registry (машиночитаемо). Упоминание стандарта не означает сертификацию.\n")
    f.write("# reviewed_at заполняет владелец при каждом цикле проверки редакций (ADR-017).\n")
    yaml.safe_dump(doc, f, allow_unicode=True, sort_keys=False, width=200)
print(len(rows), "standards")

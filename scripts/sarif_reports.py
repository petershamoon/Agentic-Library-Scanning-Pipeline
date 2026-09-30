#!/usr/bin/env python3
"""Prepare SkillSpector and Snyk Agent Scan reports for GitHub code scanning."""

import argparse
import json
from pathlib import Path

ROOT = Path.cwd().resolve()
SKILLS = (ROOT / "agentic-library" / "skills").resolve()
SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def repo_file(path: Path) -> str:
    path = path.resolve(strict=True)
    if not path.is_file() or not path.is_relative_to(ROOT):
        raise ValueError(f"Report location is not a repository file: {path}")
    return path.relative_to(ROOT).as_posix()


def write_sarif(output: Path, driver: dict, results: list) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    document = {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{"tool": {"driver": driver}, "results": results}],
    }
    output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def skillspector(raw_dir: Path, output: Path) -> None:
    driver = {"name": "SkillSpector", "rules": []}
    rules = {}
    results = []
    severity_scores = {
        "CRITICAL": 9.5,
        "HIGH": 8.0,
        "MEDIUM": 5.0,
        "LOW": 3.0,
    }

    for report_path in sorted(raw_dir.glob("*.sarif")):
        skill_dir = (SKILLS / report_path.stem).resolve()
        if not (skill_dir / "SKILL.md").is_file():
            raise ValueError(f"No SKILL.md for {report_path}")

        document = json.loads(report_path.read_text(encoding="utf-8"))
        for run in document["runs"]:
            source_driver = run["tool"]["driver"]
            if not results and not rules:
                driver = {**source_driver, "rules": []}

            for rule in source_driver.get("rules", []):
                rules.setdefault(rule["id"], rule)

            for result in run.get("results", []):
                result.pop("ruleIndex", None)
                for location in result.get("locations", []):
                    artifact = location["physicalLocation"]["artifactLocation"]
                    uri = Path(artifact["uri"])
                    if uri.is_absolute():
                        source_file = uri
                    elif (ROOT / uri).is_file() and (
                        (ROOT / uri).resolve().is_relative_to(skill_dir)
                    ):
                        source_file = ROOT / uri
                    else:
                        source_file = skill_dir / uri

                    artifact["uri"] = repo_file(source_file)
                    artifact.pop("uriBaseId", None)

                severity = str(
                    result.get("properties", {}).get("severity", "")
                ).upper()
                score = severity_scores.get(severity)
                rule_id = result.get("ruleId")
                if score and rule_id in rules:
                    properties = rules[rule_id].setdefault("properties", {})
                    current = float(properties.get("security-severity", "0"))
                    properties["security-severity"] = str(max(current, score))
                    tags = properties.setdefault("tags", [])
                    if "security" not in tags:
                        tags.append("security")

                results.append(result)

    driver["rules"] = list(rules.values())
    write_sarif(output, driver, results)


def skill_directory(scan_path: str) -> Path:
    path = Path(scan_path).expanduser()
    path = (path if path.is_absolute() else ROOT / path).resolve()
    directory = path.parent if path.name == "SKILL.md" else path

    if not directory.is_relative_to(SKILLS) or not (
        directory / "SKILL.md"
    ).is_file():
        raise ValueError(f"Cannot map Snyk scan path to a skill: {scan_path}")
    return directory


def snyk_severity(score: int) -> tuple[str, str | None]:
    # Snyk's documented levels are 100, 300, 600, and 1000.
    if score >= 1000:
        return "error", "9.5"
    if score >= 600:
        return "error", "8.0"
    if score >= 300:
        return "warning", "5.0"
    if score > 0:
        return "warning", "3.0"
    return "note", None


def snyk(input_path: Path, output: Path) -> None:
    document = json.loads(input_path.read_text(encoding="utf-8"))
    responses = document.get("scan_path_responses")
    if not isinstance(responses, list):
        raise ValueError("Unexpected Snyk JSON schema: missing scan_path_responses")

    rules = {}
    results = []

    for response in responses:
        if any(
            server.get("risk_indexes")
            for server in response.get("server_risks", [])
        ):
            raise ValueError("MCP findings need a separate location mapping")

        skill_dir = skill_directory(response["path"])
        for skill in response.get("skill_risks", []):
            for risk_name, detail in skill.get("risk_indexes", {}).items():
                score = int(detail["score"])
                level, security_severity = snyk_severity(score)
                rule_id = f"snyk-agent-scan/{risk_name}/{score}"
                title = risk_name.replace("_", " ").capitalize()

                if rule_id not in rules:
                    properties = {"tags": ["security"]}
                    if security_severity:
                        properties["security-severity"] = security_severity
                    rules[rule_id] = {
                        "id": rule_id,
                        "shortDescription": {"text": title},
                        "properties": properties,
                    }

                locations = detail.get("locations") or [None]
                for item in locations:
                    physical = {
                        "artifactLocation": {
                            "uri": repo_file(skill_dir / "SKILL.md")
                        }
                    }

                    if item:
                        start = item.get("start", {})
                        source_file = skill_dir / start.get("path", "SKILL.md")
                        physical["artifactLocation"]["uri"] = repo_file(
                            source_file
                        )
                        line = start.get("line")
                        if isinstance(line, int) and line > 0:
                            physical["region"] = {"startLine": line}

                    evidence = detail.get("evidence") or "Risk detected."
                    if item is None:
                        evidence += (
                            " Snyk did not provide a precise source line; "
                            "this alert is attached to the skill file."
                        )

                    results.append({
                        "ruleId": rule_id,
                        "level": level,
                        "message": {"text": f"{title}: {evidence}"},
                        "locations": [{"physicalLocation": physical}],
                        "properties": {"snykScore": score},
                    })

    write_sarif(
        output,
        {"name": "Snyk Agent Scan", "rules": list(rules.values())},
        results,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("scanner", choices=["skillspector", "snyk"])
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    if args.scanner == "skillspector":
        skillspector(args.input, args.output)
    else:
        snyk(args.input, args.output)


if __name__ == "__main__":
    main()

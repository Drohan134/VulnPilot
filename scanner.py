
import re
import requests
from packaging.version import Version, InvalidVersion


OSV_QUERY_URL = "https://api.osv.dev/v1/query"
REQUEST_TIMEOUT = 15


def normalize_package_name(name: str) -> str:
    """Normalize Python package names according to common PyPI conventions."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirements(text: str) -> list[dict]:
    """Parse exact-pinned requirements, e.g. requests==2.31.0."""
    packages = []
    seen = set()

    for raw_line in text.splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#") or line.startswith(("-", "git+")):
            continue

        # Remove inline comments and environment markers.
        line = line.split(";", 1)[0].split("#", 1)[0].strip()

        match = re.match(
            r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*"
            r"([A-Za-z0-9][A-Za-z0-9.!+_-]*)$",
            line,
        )

        if not match:
            continue

        name, version = match.groups()
        normalized_name = normalize_package_name(name)

        if normalized_name in seen:
            continue

        seen.add(normalized_name)
        packages.append({
            "name": name,
            "normalized_name": normalized_name,
            "version": version,
        })

    return packages


def evaluate_affected_version(
    package_version: str | None,
    affected: dict,
) -> str:
    """
    Return 'affected', 'not_affected', or 'unknown'.

    Supported ECOSYSTEM ranges are evaluated as a union of intervals.
    Explicit version evidence that conflicts with range evidence is
    treated conservatively.
    """
    if not package_version:
        return "unknown"

    try:
        current = Version(package_version)
    except (InvalidVersion, TypeError, ValueError):
        return "unknown"

    versions = affected.get("versions") or []
    ranges = affected.get("ranges") or []

    explicit_match = False

    for listed_version in versions:
        try:
            if Version(listed_version) == current:
                explicit_match = True
                break
        except (InvalidVersion, TypeError, ValueError):
            continue

    ecosystem_ranges = [
        entry
        for entry in ranges
        if entry.get("type") == "ECOSYSTEM" and entry.get("events")
    ]

    if not ecosystem_ranges:
        return "affected" if explicit_match else "unknown"

    range_results = []
    unsupported_range_found = False

    for range_entry in ecosystem_ranges:
        events = range_entry["events"]
        intervals = []
        start = None
        active = False
        supported = True

        try:
            for event in events:
                if "introduced" in event:
                    if active:
                        supported = False
                        break

                    introduced = event["introduced"]
                    start = None if introduced == "0" else Version(introduced)
                    active = True

                elif "fixed" in event:
                    if not active:
                        supported = False
                        break

                    end = Version(event["fixed"])
                    intervals.append((start, end, False))
                    start = None
                    active = False

                elif "last_affected" in event:
                    if not active:
                        supported = False
                        break

                    end = Version(event["last_affected"])
                    intervals.append((start, end, True))
                    start = None
                    active = False

                elif "limit" in event:
                    if not active:
                        supported = False
                        break

                    end = Version(event["limit"])
                    intervals.append((start, end, False))
                    start = None
                    active = False

                else:
                    supported = False
                    break

            if not supported:
                unsupported_range_found = True
                continue

            # An interval still active at the end is open-ended.
            if active:
                intervals.append((start, None, False))

            is_affected = False

            for lower, upper, inclusive_upper in intervals:
                after_lower = lower is None or current >= lower

                if upper is None:
                    before_upper = True
                elif inclusive_upper:
                    before_upper = current <= upper
                else:
                    before_upper = current < upper

                if after_lower and before_upper:
                    is_affected = True
                    break

            range_results.append(is_affected)

        except (InvalidVersion, TypeError, ValueError):
            unsupported_range_found = True
            continue

    if not range_results:
        return "affected" if explicit_match else "unknown"

    # Multiple intervals in the same advisory represent a union.
    range_says_affected = any(range_results)

    # Explicitly listed affected version conflicts with range evidence.
    if explicit_match and not range_says_affected:
        return "unknown"

    if range_says_affected:
        return "affected"

    # A negative result is only safe when all relevant ranges were parsed.
    if unsupported_range_found:
        return "unknown"

    return "not_affected"


def extract_severity(vulnerability: dict) -> str:
    """Extract severity from common OSV advisory fields."""
    database_specific = vulnerability.get("database_specific") or {}
    severity = database_specific.get("severity")

    if severity:
        return str(severity).upper()

    for affected in vulnerability.get("affected", []):
        affected_specific = affected.get("database_specific") or {}
        severity = affected_specific.get("severity")

        if severity:
            return str(severity).upper()

    # OSV may provide CVSS information without a normalized label.
    for item in vulnerability.get("severity", []):
        if item.get("type", "").upper().startswith("CVSS"):
            score = item.get("score", "")
            match = re.search(r"CVSS:[0-9.]+/.*", score)

            # A vector alone is not a numeric severity score.
            if match:
                continue

    return "Unknown"


def query_osv(package: dict) -> dict:
    """Query OSV for one dependency and preserve API errors."""
    if not package.get("version"):
        return {
            "status": "error",
            "message": "Package version is missing.",
            "vulnerabilities": [],
        }

    payload = {
        "package": {
            "name": package["name"],
            "ecosystem": "PyPI",
        },
        "version": package["version"],
    }

    try:
        response = requests.post(
            OSV_QUERY_URL,
            json=payload,
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        data = response.json()

    except requests.RequestException as exc:
        return {
            "status": "error",
            "message": str(exc),
            "vulnerabilities": [],
        }
    except ValueError as exc:
        return {
            "status": "error",
            "message": f"Invalid JSON response from OSV: {exc}",
            "vulnerabilities": [],
        }

    vulnerabilities = []

    for vuln in data.get("vulns", []):
        affected_records = [
            record
            for record in vuln.get("affected", [])
            if record.get("package", {}).get("ecosystem") == "PyPI"
            and normalize_package_name(
                record.get("package", {}).get("name", "")
            ) == package["normalized_name"]
        ]

        applicability_values = [
            evaluate_affected_version(package["version"], record)
            for record in affected_records
        ]

        if "affected" in applicability_values:
            applicability = "affected"
        elif (
            applicability_values
            and all(value == "not_affected" for value in applicability_values)
        ):
            applicability = "not_affected"
        else:
            applicability = "unknown"

        references = [
            item.get("url")
            for item in vuln.get("references", [])
            if item.get("url")
        ]

        vulnerabilities.append({
            "package": package["name"],
            "version": package["version"],
            "id": vuln.get("id", "Unknown"),
            "summary": vuln.get("summary") or "No summary supplied by OSV.",
            "details": vuln.get("details") or "",
            "aliases": vuln.get("aliases") or [],
            "severity": extract_severity(vuln),
            "applicability": applicability,
            "affected_records": affected_records,
            "references": references,
        })

    return {
        "status": "checked",
        "message": "OSV query completed.",
        "vulnerabilities": vulnerabilities,
    }



def deduplicate_findings(findings: list[dict]) -> list[dict]:
    """Merge duplicate advisory records using shared IDs and aliases."""

    if not findings:
        return []

    parent = list(range(len(findings)))

    def find(index):
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(first, second):
        root_a = find(first)
        root_b = find(second)
        if root_a != root_b:
            parent[root_b] = root_a

    # Only compare findings for the same normalized package and version.
    identifier_owner = {}

    for index, finding in enumerate(findings):
        package_key = normalize_package_name(finding.get("package", ""))
        version_key = finding.get("version", "")

        identifiers = {
            str(value).strip().upper()
            for value in [
                finding.get("id", ""),
                *(finding.get("aliases") or []),
            ]
            if value and str(value).strip()
        }

        group_key = (package_key, version_key)

        for identifier in identifiers:
            key = (group_key, identifier)

            if key in identifier_owner:
                union(index, identifier_owner[key])
            else:
                identifier_owner[key] = index

    # Collect connected components.
    components = {}
    for index, finding in enumerate(findings):
        components.setdefault(find(index), []).append(finding)

    merged_findings = []

    for records in components.values():
        merged = dict(records[0])

        all_ids = []
        all_aliases = []
        all_references = []
        all_affected_records = []

        def append_unique(target, values):
            for value in values:
                if value and value not in target:
                    target.append(value)

        for record in records:
            append_unique(all_ids, [record.get("id")])
            append_unique(all_ids, record.get("aliases") or [])
            append_unique(all_aliases, record.get("aliases") or [])
            append_unique(all_references, record.get("references") or [])
            append_unique(
                all_affected_records,
                record.get("affected_records") or [],
            )

        # Prefer a GHSA identifier as the primary display ID when available.
        primary_id = next(
            (value for value in all_ids if value.upper().startswith("GHSA-")),
            records[0].get("id", "Unknown"),
        )

        merged["id"] = primary_id
        merged["aliases"] = [
            value for value in all_ids if value != primary_id
        ]
        merged["references"] = all_references
        merged["affected_records"] = all_affected_records

        # Retain every original record for auditability.
        merged["advisory_records"] = [dict(record) for record in records]
        merged["advisory_ids"] = all_ids
        merged["duplicate_count"] = len(records)

        # Do not silently discard differences in severity.
        merged["severity_values"] = list(dict.fromkeys(
            str(record.get("severity", "UNKNOWN"))
            for record in records
        ))

        merged_findings.append(merged)

    return merged_findings


def scan_requirements(text: str) -> dict:
    """Scan parsed requirements and return structured findings."""
    packages = parse_requirements(text)

    if not packages:
        return {
            "status": "error",
            "message": (
                "No supported requirements found. "
                "Use pinned versions, e.g. requests==2.31.0."
            ),
            "packages": [],
            "findings": [],
            "errors": [],
        }

    findings = []
    errors = []
    package_results = []

    for package in packages:
        result = query_osv(package)

        if result["status"] == "error":
            errors.append({
                "package": package["name"],
                "version": package["version"],
                "message": result["message"],
            })
            package_results.append({
                **package,
                "status": "error",
                "message": result["message"],
            })
            continue

        package_results.append({
            **package,
            "status": "checked",
            "message": result["message"],
        })

        findings.extend(result["vulnerabilities"])

    if errors and not package_results:
        status = "error"
    elif errors:
        status = "partial"
    else:
        status = "completed"
        
    findings = deduplicate_findings(findings)
    checked_count = sum(
        item["status"] == "checked" for item in package_results
    )

    return {
        "status": status,
        "message": (
            f"Checked {checked_count} package(s); "
            f"found {len(findings)} advisory result(s)."
        ),
        "packages": package_results,
        "findings": findings,
        "errors": errors,
    }


if __name__ == "__main__":
    sample = "django==1.2\nrequests==2.31.0\nflask==2.0.0"
    import json
    print(json.dumps(scan_requirements(sample), indent=2))

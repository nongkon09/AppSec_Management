"""SBOM format detection and parsing (Requirement.md FR-2.6.1, FR-9.1).

Used only by the manual/COTS upload path (FR-2.6): the automated CI/CD flow pushes
straight to Dependency-Track and never touches this platform (FR-2.7), so this parser
exists to (a) validate the uploaded file's format before accepting it and (b) extract
Components directly so a manual upload is immediately useful even before Dependency-Track
has processed it.

Supports CycloneDX JSON (primary, FR-2.1) and SPDX 2.x JSON (for License Compliance,
FR-2.1/FR-9.1).
"""

import json
from dataclasses import dataclass


class SbomFormatError(ValueError):
    """Raised when the uploaded file is not a recognizable CycloneDX or SPDX document."""


@dataclass(frozen=True)
class ParsedComponent:
    name: str
    version: str | None
    license: str | None
    purl: str | None
    scope: str  # "production" / "development" (FR-4.2)


@dataclass(frozen=True)
class ParsedSbom:
    sbom_format: str  # "cyclonedx" / "spdx"
    spec_version: str | None
    components: list[ParsedComponent]


def _cyclonedx_license(component: dict) -> str | None:
    licenses = component.get("licenses") or []
    for entry in licenses:
        license_obj = entry.get("license") or {}
        if license_obj.get("id"):
            return str(license_obj["id"])
        if license_obj.get("name"):
            return str(license_obj["name"])
        if entry.get("expression"):
            return str(entry["expression"])
    return None


def _cyclonedx_scope(component: dict) -> str:
    """FR-4.2: CycloneDX's own `scope` field distinguishes required/optional/excluded
    dependencies; generators also sometimes flag dev-only deps via a property instead."""
    if str(component.get("scope", "")).lower() in {"optional", "excluded"}:
        return "development"
    for prop in component.get("properties") or []:
        name = str(prop.get("name", "")).lower()
        if "development" in name and str(prop.get("value", "")).lower() == "true":
            return "development"
    return "production"


def parse_cyclonedx(data: dict) -> ParsedSbom:
    if data.get("bomFormat") != "CycloneDX":
        raise SbomFormatError("Not a CycloneDX document (missing bomFormat: 'CycloneDX')")
    spec_version = data.get("specVersion")
    components = [
        ParsedComponent(
            name=(
                f"{component['group']}:{component['name']}"
                if component.get("group")
                else component.get("name", "unknown")
            ),
            version=component.get("version"),
            license=_cyclonedx_license(component),
            purl=component.get("purl"),
            scope=_cyclonedx_scope(component),
        )
        for component in data.get("components", [])
        if component.get("name")
    ]
    return ParsedSbom(sbom_format="cyclonedx", spec_version=spec_version, components=components)


def _spdx_purl(package: dict) -> str | None:
    for ref in package.get("externalRefs", []):
        if ref.get("referenceType") == "purl":
            return str(ref.get("referenceLocator"))
    return None


def _spdx_license(package: dict) -> str | None:
    for key in ("licenseConcluded", "licenseDeclared"):
        value = package.get(key)
        if value and value not in ("NOASSERTION", "NONE"):
            return str(value)
    return None


def parse_spdx(data: dict) -> ParsedSbom:
    if "spdxVersion" not in data:
        raise SbomFormatError("Not an SPDX document (missing 'spdxVersion')")
    spec_version = data.get("spdxVersion")
    components = [
        ParsedComponent(
            name=package.get("name", "unknown"),
            version=package.get("versionInfo"),
            license=_spdx_license(package),
            purl=_spdx_purl(package),
            # SPDX has no first-class production/development dependency scope field.
            scope="production",
        )
        for package in data.get("packages", [])
        if package.get("name")
    ]
    return ParsedSbom(sbom_format="spdx", spec_version=spec_version, components=components)


def parse_sbom(raw_bytes: bytes) -> ParsedSbom:
    """Detects CycloneDX vs SPDX JSON and parses accordingly.

    Raises `SbomFormatError` for anything else — invalid JSON, or JSON that is neither —
    so an upload is rejected before it reaches the database (FR-2.6.1: "ผ่านการตรวจสอบ
    Format ก่อนรับเข้า" — validate format before accepting).
    """
    try:
        data = json.loads(raw_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise SbomFormatError(f"File is not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise SbomFormatError("Expected a JSON object at the top level")

    if data.get("bomFormat") == "CycloneDX":
        return parse_cyclonedx(data)
    if "spdxVersion" in data:
        return parse_spdx(data)
    raise SbomFormatError(
        "Unrecognized SBOM format: expected CycloneDX (bomFormat: 'CycloneDX') "
        "or SPDX (spdxVersion present)"
    )

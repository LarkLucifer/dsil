"""
Report rendering for DSIL.
"""

from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .schemas import Report, FindingRecord


class ReportRenderer:
    """
    Renders DSIL reports in JSON, Markdown, HTML, and HackerOne formats.
    """

    def __init__(self, report: Report) -> None:
        self.report = report

    def to_json(self) -> str:
        return json.dumps(self.report.to_dict(), indent=2, sort_keys=False)

    def to_markdown(self) -> str:
        lines: list[str] = []
        lines.append("# DSIL Report")
        lines.append("")
        lines.append(f"**Target:** {self.report.target}")
        lines.append(f"**Mode:** {self.report.mode}")
        lines.append(f"**Started:** {self.report.started_at}")
        lines.append(f"**Finished:** {self.report.finished_at}")
        lines.append(f"**Duration:** {self.report.duration_seconds:.2f}s")
        lines.append("")

        if self.report.executive_summary:
            lines.append("## Executive Summary")
            lines.append("")
            lines.append(self.report.executive_summary)
            lines.append("")

        if not self.report.verified_findings:
            lines.append("No verified findings.")
            return "\n".join(lines)

        lines.append("## Findings")
        lines.append("")

        for idx, f in enumerate(self.report.verified_findings, start=1):
            lines.append(f"### {idx}. {f.name} ({f.severity.upper()})")
            lines.append("")
            lines.append("**Summary**")
            lines.append(f"- Finding ID: `{f.id}`")
            lines.append(f"- URL: {f.url}")
            lines.append(f"- Confidence: {f.confidence:.2f}")
            if f.cvss_vector and f.cvss_score is not None:
                lines.append(f"- CVSS: {f.cvss_vector} ({f.cvss_score:.1f})")
            lines.append("")

            lines.append("**Description**")
            lines.append(
                "This issue was identified during automated scanning and verified in a follow-up check."
            )
            lines.append("")

            lines.append("**Evidence**")
            lines.append("```json")
            lines.append(json.dumps(f.evidence, indent=2, ensure_ascii=True))
            lines.append("```")
            lines.append("")

            lines.append("**Remediation**")
            lines.append(f.remediation or self._remediation_for(f))
            lines.append("")

        return "\n".join(lines)

    def to_h1_markdown(self) -> str:
        lines: list[str] = [
            f"# Security Assessment Report: {self.report.target}",
            "",
            "## Summary",
            self.report.executive_summary or "Verified security findings identified during automated scanning.",
            "",
            "## Findings Overview",
            "| ID | Vulnerability | Severity | URL |",
            "|----|---------------|----------|-----|"
        ]

        if not self.report.verified_findings:
            lines.append("| N/A | No verified findings | - | - |")
        else:
            for f in self.report.verified_findings:
                lines.append(f"| {f.id} | {f.name} | {f.severity.upper()} | `{f.url}` |")

        lines.extend(["", "---", ""])

        for f in self.report.verified_findings:
            curl_cmd = self._curl_for(f)
            lines.extend([
                f"## {f.name}",
                "",
                "### Description",
                f"The target application at `{f.url}` is vulnerable to **{f.name}**. This issue was verified using automated techniques with a confidence level of {f.confidence*100:.0f}%.",
                "",
                "### Steps to Reproduce",
                "Execute the following curl command to observe the vulnerability:",
                "```bash",
                curl_cmd,
                "```",
                "",
                "### Impact",
                self._impact_for(f),
                "",
                "### Remediation",
                f.remediation or self._remediation_for(f),
                "",
                "---",
                ""
            ])

        return "\n".join(lines)

    def _impact_for(self, finding: FindingRecord) -> str:
        impacts = {
            "XSS": "An attacker can execute arbitrary JavaScript in the victim's browser, enabling session hijacking, credential theft, or unintended actions on behalf of the user.",
            "SSRF": "An attacker can pivot through the server to access internal services, cloud metadata endpoints, or other restricted network resources.",
            "PP": "Manipulating the object prototype can lead to logic bypasses, denial of service, or in some cases, remote code execution.",
            "HDR": "Missing security headers reduce the browser's ability to protect users from common attacks like Clickjacking or XSS.",
            "SAST": "Exposed credentials or sensitive logic in client-side code can lead to full account takeovers or exposure of backend secrets."
        }
        for key, val in impacts.items():
            if key in finding.id or key in finding.name.upper():
                return val
        return "This vulnerability may compromise the integrity or confidentiality of user data and system operations."

    def to_html(self) -> str:
        template_dir = Path(__file__).parent / "templates"
        env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(["html", "xml"]),
        )
        template = env.get_template("report.html.j2")

        severity_counts = self._severity_counts(self.report.verified_findings)
        return template.render(
            report=self.report,
            severity_counts=severity_counts,
            findings=self.report.verified_findings,
        )

    def write_reports(self, out_dir: Path, stem: str) -> tuple[Path, Path, Path, Path]:
        out_dir.mkdir(parents=True, exist_ok=True)

        json_path = out_dir / f"{stem}.json"
        md_path = out_dir / f"{stem}.md"
        html_path = out_dir / f"{stem}.html"
        h1_path = out_dir / f"{stem}_h1_report.md"

        json_path.write_text(self.to_json(), encoding="utf-8")
        md_path.write_text(self.to_markdown(), encoding="utf-8")
        html_path.write_text(self.to_html(), encoding="utf-8")
        h1_path.write_text(self.to_h1_markdown(), encoding="utf-8")

        return json_path, md_path, html_path, h1_path

    def _severity_counts(self, findings: list[FindingRecord]) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            key = f.severity.lower()
            if key in counts:
                counts[key] += 1
        return counts

    def _remediation_for(self, finding: FindingRecord) -> str:
        if finding.id == "HDR-001":
            return (
                "Add standard security headers such as Content-Security-Policy, "
                "X-Frame-Options, X-Content-Type-Options, and Referrer-Policy to all "
                "HTML responses."
            )
        if finding.id == "OOB-001":
            return "Review server-side request handling to ensure untrusted input cannot trigger external callbacks."
        if finding.id == "PP-001":
            return "Validate and sanitize user-controlled keys before merging into objects. Consider safe object cloning."
        if finding.id == "SAST-JS-001":
            return "Remove secrets from client-side code, rotate exposed keys, and move sensitive logic server-side."
        if finding.id == "REFLECT-001" or "XSS" in finding.id:
            return "Apply strict output encoding (e.g., HTML entity encoding) to all user-kontrolled data reflected in the response. Use a Content Security Policy (CSP) to mitigate potential impact."
        if "SSRF" in finding.id:
            return "Implement a strict allowlist for outgoing requests. Avoid passing user-controlled URLs directly to networking libraries. If internal access is required, use a dedicated proxy with minimized privileges."
        return "Investigate and remediate the issue according to secure coding best practices (OWASP Top 10)."

    def _curl_for(self, finding: FindingRecord) -> str:
        url = finding.url
        if isinstance(finding.evidence, dict):
            url = finding.evidence.get("url", url)
        return f"curl -i \"{url}\""

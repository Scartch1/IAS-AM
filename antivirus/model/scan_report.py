from dataclasses import dataclass, field
from typing import List

from antivirus.model.scan_result import ScanResult
from antivirus.model.scan_status import ScanStatus
from antivirus.model.threat import Threat


@dataclass
class ScanReport:
    """Aggregate result for a directory or batch scan."""

    total_files: int = 0
    clean_files: int = 0
    threat_files: int = 0
    error_files: int = 0
    results: List[ScanResult] = field(default_factory=list)
    duration: float = 0.0
    skipped_files: int = 0
    cancelled: bool = False
    warnings: list[str] = field(default_factory=list)
    started_at: str = ""
    completed_at: str = ""

    @property
    def outcome(self) -> str:
        if self.cancelled:
            return "cancelled"
        if self.threat_files:
            return "detected"
        if self.error_files or self.skipped_files or self.warnings:
            return "partial" if self.clean_files else "error"
        return "clean" if self.total_files else "empty"

    @property
    def threats_found(self) -> int:
        return sum(len(result.threats) for result in self.results)

    @property
    def incomplete_files(self) -> int:
        return (
            self.error_files
            + self.skipped_files
            + sum(
                1
                for result in self.results
                if result.is_detected and result.error_message
            )
        )

    def add_result(self, result: ScanResult) -> None:
        self.results.append(result)
        self.warnings.extend(result.warnings)
        if result.started_at and (
            not self.started_at or result.started_at < self.started_at
        ):
            self.started_at = result.started_at
        if result.completed_at and (
            not self.completed_at or result.completed_at > self.completed_at
        ):
            self.completed_at = result.completed_at
        self.duration += result.scan_duration
        self.total_files += 1
        if result.is_detected:
            self.threat_files += 1
            if result.error_message:
                self.warnings.append(
                    f"A suspicious file also had incomplete checks: {result.file_path}"
                )
        elif result.status.value == "error":
            self.error_files += 1
        elif result.status.value == "skipped":
            self.skipped_files += 1
        elif result.is_clean:
            self.clean_files += 1
        else:
            self.error_files += 1

    @classmethod
    def from_dict(cls, payload: dict) -> "ScanReport":
        """Restore a previously saved JSON report for the History results dialog."""

        summary = payload.get("summary", {}) if isinstance(payload, dict) else {}
        report = cls()
        for item in payload.get("results", []) if isinstance(payload, dict) else []:
            if not isinstance(item, dict):
                continue
            try:
                status = ScanStatus(item.get("status", "error"))
            except ValueError:
                status = ScanStatus.ERROR
            threats = [
                Threat(
                    name=str(threat.get("name", "Unknown detection")),
                    category=str(threat.get("category", "Unknown")),
                    severity=str(threat.get("severity", "Medium")),
                    description=str(threat.get("description", "")),
                    source=str(threat.get("source", "unknown")),
                )
                for threat in item.get("threats", [])
                if isinstance(threat, dict)
            ]
            report.add_result(
                ScanResult(
                    file_path=str(item.get("file_path", "Unknown file")),
                    status=status,
                    threats=threats,
                    sha256=item.get("sha256"),
                    scan_duration=float(item.get("scan_duration_seconds", 0) or 0),
                    detection_methods=list(item.get("detection_methods", []) or []),
                    error_message=item.get("error_message"),
                    engine_results=dict(item.get("engine_results", {}) or {}),
                    warnings=list(item.get("warnings", []) or []),
                    started_at=str(item.get("started_at", "")),
                    completed_at=str(item.get("completed_at", "")),
                )
            )

        report.total_files = int(summary.get("total_files", report.total_files) or 0)
        report.clean_files = int(summary.get("clean_files", report.clean_files) or 0)
        report.threat_files = int(summary.get("threat_files", report.threat_files) or 0)
        report.error_files = int(summary.get("error_files", report.error_files) or 0)
        report.skipped_files = int(summary.get("skipped_files", report.skipped_files) or 0)
        report.cancelled = bool(summary.get("cancelled", False))
        report.duration = float(summary.get("duration_seconds", report.duration) or 0)
        report.warnings = list(summary.get("warnings", report.warnings) or [])
        report.started_at = str(summary.get("started_at", report.started_at) or "")
        report.completed_at = str(summary.get("completed_at", report.completed_at) or "")
        return report

    @classmethod
    def from_history_record(cls, record: dict) -> "ScanReport":
        """Show a useful summary for history records saved before report storage."""

        report = cls(
            total_files=int(record.get("file_count", 0) or 0),
            clean_files=int(record.get("clean_files", 0) or 0),
            threat_files=int(record.get("threats_found", 0) or 0),
            error_files=int(record.get("error_files", 0) or 0),
            skipped_files=int(record.get("skipped_files", 0) or 0),
            warnings=list(record.get("warnings", []) or []),
            started_at=str(record.get("started_at", "") or ""),
            completed_at=str(record.get("completed_at", "") or ""),
            duration=float(record.get("duration", 0) or 0),
        )
        report.warnings.append(
            "This older history entry contains only a summary; individual file results were not stored."
        )
        return report

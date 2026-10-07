"""Coordinates scan views with the existing backend scanner."""

from antivirus.model.scan_result import ScanResult
from antivirus.model.scan_report import ScanReport
from antivirus.services.report_formatter import ReportFormatter
from antivirus.services.scanner import Scanner
from antivirus.repository.scan_repository import ScanRepository
from pathlib import Path
from time import monotonic
from datetime import datetime, timezone, timedelta
from antivirus.utils.logging import get_logger

logger = get_logger(__name__)


class ScanController:
    def __init__(
        self, scanner: Scanner | None = None, repository: ScanRepository | None = None
    ) -> None:
        self.scanner = scanner or Scanner()
        self.repository = repository or ScanRepository()

    def scan_file(self, file_path: str) -> ScanResult:
        started = monotonic()
        result = self.scanner.scan_file(file_path)
        self._record_report(
            self._as_report(result),
            file_path,
            "file",
            monotonic() - started,
        )
        return result

    def scan_directory(
        self, directory_path: str, progress_callback=None, cancel_check=None
    ) -> ScanReport:
        started = monotonic()
        report = self.scanner.scan_directory(
            directory_path, progress_callback, cancel_check
        )
        self._record_report(
            report,
            directory_path,
            "folder",
            monotonic() - started,
            "cancelled" if report.cancelled else None,
        )
        return report

    def quick_scan(self, progress_callback=None, cancel_check=None) -> ScanReport:
        started = monotonic()
        home = Path.home()
        preferred = [home / name for name in ("Desktop", "Downloads", "Documents")]
        roots = [path for path in preferred if path.is_dir()]
        if not roots:
            report = ScanReport(
                warnings=[
                    "No Desktop, Downloads, or Documents folders were found. Choose a folder manually."
                ]
            )
            self._record_report(report, str(home), "quick", monotonic() - started)
            return report
        report = self.scanner.scan_directories(
            [str(path) for path in roots], progress_callback, cancel_check
        )
        self._record_report(
            report,
            ", ".join(str(path) for path in roots),
            "quick",
            monotonic() - started,
            "cancelled" if report.cancelled else None,
        )
        return report

    def scan_drives(
        self, roots: list[str], progress_callback=None, cancel_check=None
    ) -> ScanReport:
        """Scan only the explicitly chosen roots, sharing traversal and size limits."""
        started = monotonic()
        report = self.scanner.scan_directories(roots, progress_callback, cancel_check)
        self._record_report(
            report,
            ", ".join(roots),
            "drives",
            monotonic() - started,
            "cancelled" if report.cancelled else None,
        )
        return report

    @staticmethod
    def _as_report(result: ScanResult) -> ScanReport:
        report = ScanReport()
        report.add_result(result)
        return report

    def _record_report(
        self,
        report: ScanReport,
        target: str,
        scan_type: str,
        duration: float,
        status_override: str | None = None,
    ) -> None:
        status = status_override or report.outcome
        report.duration = duration
        completed = datetime.now(timezone.utc)
        report.started_at = (
            report.started_at or (completed - timedelta(seconds=duration)).isoformat()
        )
        report.completed_at = report.completed_at or completed.isoformat()
        threats = [
            {
                "name": threat.name,
                "category": threat.category,
                "severity": threat.severity,
            }
            for result in report.results
            for threat in result.threats
        ]
        try:
            self.repository.record_scan(
                report.total_files,
                report.threats_found,
                report.clean_files,
                report.error_files,
                status,
                started_at=report.started_at,
                completed_at=report.completed_at,
                target=target,
                scan_type=scan_type,
                duration=duration,
                threats=threats,
                skipped_files=report.skipped_files,
                warnings=report.warnings,
                report=ReportFormatter.to_dict(report),
            )
        except Exception:
            logger.exception("Could not persist scan history")
            report.warnings.append(
                "Results are available, but history could not be saved. Export this report."
            )
            if scan_type == "file" and report.results:
                report.results[0].warnings.extend(report.warnings)

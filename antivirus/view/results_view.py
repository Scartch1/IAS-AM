"""Scan-results table, details, filtering, and report export."""

from __future__ import annotations

from pathlib import Path
import json
import os

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from antivirus.services.report_formatter import ReportFormatter
from antivirus.services.report_signer import ReportSigner
from antivirus.model.scan_status import ScanStatus
from antivirus.view.theme import status_color
from antivirus.view.components import (
    EmptyState,
    MetricCard,
    configure_table,
    page_header,
)


class ResultsView(QWidget):
    quarantine_requested = Signal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.report = None
        self._page_index = 0
        self._page_size = 250

        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 27, 30, 26)
        layout.setSpacing(16)

        heading = QHBoxLayout()
        heading.addWidget(
            page_header(
                "Scan results",
                "Review what was checked, inspect detections, and export a clear report.",
            ),
            1,
        )
        self.export_json_button = QPushButton("Export JSON", self)
        self.export_csv_button = QPushButton("Export CSV", self)
        self.export_signed_button = QPushButton("Signed JSON", self)
        self.export_signed_button.setToolTip(
            "Signs the report with Ed25519. Verify using a separately trusted public key."
        )
        self.export_signed_button.clicked.connect(lambda: self._export("signed.json"))
        self.export_json_button.clicked.connect(lambda: self._export("json"))
        self.export_csv_button.clicked.connect(lambda: self._export("csv"))
        self.export_json_button.setEnabled(False)
        self.export_csv_button.setEnabled(False)
        self.export_signed_button.setEnabled(False)
        heading.addWidget(self.export_json_button)
        heading.addWidget(self.export_csv_button)
        heading.addWidget(self.export_signed_button)
        layout.addLayout(heading)

        metrics = QHBoxLayout()
        metrics.setSpacing(13)
        self.total_card = MetricCard("F", "Files checked")
        self.clean_card = MetricCard("✓", "No matches")
        self.threat_card = MetricCard("!", "Suspicious files")
        self.error_card = MetricCard("E", "Incomplete / skipped")
        for card in (
            self.total_card,
            self.clean_card,
            self.threat_card,
            self.error_card,
        ):
            metrics.addWidget(card, 1)
        layout.addLayout(metrics)

        self.results_toolbar = QWidget(self)
        toolbar = QHBoxLayout(self.results_toolbar)
        toolbar.setContentsMargins(0, 0, 0, 0)
        self.summary = QLabel("", self.results_toolbar)
        self.summary.setProperty("role", "muted")
        self.filter_combo = QComboBox(self.results_toolbar)
        self.filter_combo.addItems(
            [
                "All results",
                "Threats only",
                "No matches only",
                "Errors only",
                "Skipped only",
            ]
        )
        self.filter_combo.currentIndexChanged.connect(self._reset_page)
        self.search_box = QLineEdit(self.results_toolbar)
        self.search_box.setPlaceholderText("Find file or detection…")
        self.search_box.setAccessibleName("Search scan results")
        self.search_box.setMaximumWidth(230)
        self.search_box.textChanged.connect(self._reset_page)
        toolbar.addWidget(self.summary, 1)
        toolbar.addWidget(self.search_box)
        toolbar.addWidget(QLabel("Show:", self.results_toolbar))
        toolbar.addWidget(self.filter_combo)
        layout.addWidget(self.results_toolbar)
        self.results_toolbar.hide()

        actions = QHBoxLayout()
        instructions = QLabel(
            "Ctrl-click to choose files, Shift-click for a range, or Ctrl+A for this page. "
            "Only detected files with a scan hash can be quarantined.",
            self,
        )
        instructions.setProperty("role", "hint")
        instructions.setWordWrap(True)
        self.quarantine_button = QPushButton("Quarantine selected", self)
        self.quarantine_button.setProperty("variant", "primary")
        self.quarantine_button.setEnabled(False)
        self.quarantine_button.clicked.connect(self._request_quarantine)
        self._vault_busy = False
        self._isolated = set()
        actions.addWidget(instructions, 1)
        actions.addWidget(self.quarantine_button)
        layout.addLayout(actions)

        self.table = QTableWidget(0, 5, self)
        self.table.setHorizontalHeaderLabels(
            ["File", "Status", "Threat", "Severity", "Checks completed"]
        )
        configure_table(self.table)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.horizontalHeader().setStretchLastSection(False)
        self.table.setColumnWidth(0, 285)
        self.table.setColumnWidth(1, 110)
        self.table.setColumnWidth(2, 220)
        self.table.setColumnWidth(3, 85)
        self.table.setColumnWidth(4, 120)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.cellDoubleClicked.connect(self._show_details)
        self.table.itemSelectionChanged.connect(self._update_quarantine_action)
        self.table.hide()
        layout.addWidget(self.table, 1)

        self.empty_state = EmptyState(
            "○",
            "No scan results yet",
            "Run a quick scan or choose a file or folder to see results here.",
            self,
        )
        layout.addWidget(self.empty_state, 1)

        self.pagination = QWidget(self)
        pagination_layout = QHBoxLayout(self.pagination)
        pagination_layout.setContentsMargins(0, 0, 0, 0)
        self.page_label = QLabel(self.pagination)
        self.page_label.setProperty("role", "muted")
        self.previous_button = QPushButton("Previous", self.pagination)
        self.next_button = QPushButton("Next", self.pagination)
        self.previous_button.clicked.connect(lambda: self._change_page(-1))
        self.next_button.clicked.connect(lambda: self._change_page(1))
        pagination_layout.addWidget(self.page_label, 1)
        pagination_layout.addWidget(self.previous_button)
        pagination_layout.addWidget(self.next_button)
        layout.addWidget(self.pagination)
        self.pagination.hide()

    def _reset_page(self, *_args):
        self._page_index = 0
        self._render_rows()

    def _change_page(self, difference):
        self._page_index = max(0, self._page_index + difference)
        self._render_rows()

    def show_report(self, report):
        self.report = report
        self._isolated.clear()
        self._page_index = 0
        self.total_card.set_value(report.total_files)
        self.clean_card.set_value(report.clean_files)
        self.threat_card.set_value(report.threat_files)
        self.error_card.set_value(report.incomplete_files)
        self.summary.setText(
            f"{report.total_files} file{'s' if report.total_files != 1 else ''} checked · "
            f"{report.threats_found} detection{'s' if report.threats_found != 1 else ''} · {report.outcome.title()}"
            + (" · " + report.warnings[0][:160] if report.warnings else "")
        )
        self.summary.setWordWrap(True)
        self.summary.setTextFormat(Qt.TextFormat.PlainText)
        self.summary.setToolTip(
            "No matches means the enabled engines found no known pattern. It is not a guarantee that a file is safe."
        )
        self.export_json_button.setEnabled(True)
        self.export_csv_button.setEnabled(True)
        self.export_signed_button.setEnabled(True)
        self.results_toolbar.show()
        self.filter_combo.setCurrentIndex(0)
        self._render_rows()

    def _render_rows(self, *_args):
        self.table.setRowCount(0)
        if self.report is None:
            self.table.hide()
            self.empty_state.show()
            return

        filter_index = self.filter_combo.currentIndex()
        query = self.search_box.text().casefold().strip()
        results = [
            result
            for result in self.report.results
            if (
                filter_index == 0
                or (filter_index == 1 and result.is_detected)
                or (filter_index == 2 and result.is_clean)
                or (filter_index == 3 and result.status.value == "error")
                or (filter_index == 4 and result.status.value == "skipped")
            )
            and (
                not query
                or query in result.file_path.casefold()
                or any(query in threat.name.casefold() for threat in result.threats)
            )
        ]
        count = len(results)
        pages = max(1, (count + self._page_size - 1) // self._page_size)
        self._page_index = min(self._page_index, pages - 1)
        self.page_label.setText(
            f"Page {self._page_index + 1} of {pages} · {count} matching files · exports include every result"
        )
        self.previous_button.setEnabled(self._page_index > 0)
        self.next_button.setEnabled(self._page_index + 1 < pages)
        self.pagination.setVisible(count > self._page_size)
        start = self._page_index * self._page_size
        results = results[start : start + self._page_size]

        for result in results:
            row = self.table.rowCount()
            self.table.insertRow(row)
            threats = ", ".join(threat.name for threat in result.threats) or "—"
            severities = (
                ", ".join(dict.fromkeys(threat.severity for threat in result.threats))
                or "—"
            )
            methods = (
                ", ".join(result.checked_engines or result.detection_methods) or "None"
            )
            values = [
                result.file_path,
                (
                    "No matches"
                    if result.status == ScanStatus.CLEAN
                    else result.status.value.title()
                ),
                threats,
                severities,
                methods,
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setToolTip(str(value))
                if column == 0:
                    item.setData(Qt.ItemDataRole.UserRole, result)
                if column == 1:
                    item.setForeground(QColor(status_color(result.status.value)))
                self.table.setItem(row, column, item)

        has_rows = bool(results)
        self.table.setVisible(has_rows)
        self.empty_state.setVisible(not has_rows)
        if self.report.results and not has_rows:
            self.empty_state.set_message(
                "No matching results", "Choose a different result filter to continue."
            )
        elif not self.report.results:
            self.empty_state.set_message(
                "No files found", "The selected location did not contain any files."
            )

        self._update_quarantine_action()

    def _selected_results(self):
        results = []
        for index in sorted(
            self.table.selectionModel().selectedRows(), key=lambda i: i.row()
        ):
            item = self.table.item(index.row(), 0)
            if item and item.data(Qt.ItemDataRole.UserRole) is not None:
                results.append(item.data(Qt.ItemDataRole.UserRole))
        return results

    def _eligible_results(self):
        return [
            result
            for result in self._selected_results()
            if result.is_detected
            and result.sha256
            and self._quarantine_key(result.file_path, result.sha256)
            not in self._isolated
        ]

    def _update_quarantine_action(self):
        selected = self._selected_results()
        eligible = self._eligible_results()
        isolated = bool(selected) and all(
            self._quarantine_key(result.file_path, result.sha256) in self._isolated
            for result in selected
        )
        self.quarantine_button.setEnabled(bool(eligible) and not self._vault_busy)
        self.quarantine_button.setText(
            "Already isolated"
            if isolated
            else (
                f"Quarantine selected ({len(eligible)})"
                if eligible
                else "Quarantine selected"
            )
        )
        self.quarantine_button.setToolTip(
            f"{len(eligible)} eligible of {len(selected)} selected files on this page."
        )

    def set_vault_busy(self, busy):
        self._vault_busy = busy
        self._update_quarantine_action()

    def quarantine_changed(self, entry):
        key = self._quarantine_key(entry.original_path, entry.sha256)
        if entry.state == "active":
            self._isolated.add(key)
        elif entry.state == "restored":
            self._isolated.discard(key)
        self._update_quarantine_action()

    @staticmethod
    def _quarantine_key(path, sha256):
        return (
            os.path.normcase(os.path.abspath(os.path.expanduser(path))),
            (sha256 or "").lower(),
        )

    def _request_quarantine(self):
        results = self._eligible_results()
        if results and self.quarantine_button.isEnabled():
            self.quarantine_requested.emit(results[0] if len(results) == 1 else results)

    def _show_details(self, row, _column):
        item = self.table.item(row, 0)
        result = item.data(Qt.ItemDataRole.UserRole) if item else None
        if result is None:
            return
        threat_lines = []
        for threat in result.threats:
            threat_lines.append(
                f"• {threat.name} ({threat.severity})\n  {threat.description or 'No additional description.'}"
            )
        threat_text = "\n".join(threat_lines) or "No threats detected."
        engine_text = (
            "\n".join(f"{key}: {value}" for key, value in result.engine_results.items())
            or "No engine details"
        )
        dialog = QMessageBox(self)
        dialog.setWindowTitle("Scan details")
        dialog.setTextFormat(Qt.TextFormat.PlainText)
        dialog.setText(
            f"File\n{result.file_path}\n\nStatus\n{result.status.value.title()}\n\n"
            f"SHA-256\n{result.sha256 or 'Unavailable'}\n\nDetections\n{threat_text}\n\n"
            f"Engine outcomes\n{engine_text}"
            + (f"\n\nNote\n{result.error_message}" if result.error_message else ""),
        )
        dialog.exec()

    def _export(self, format_name: str):
        if self.report is None:
            return
        extension = format_name.lower()
        path, _ = QFileDialog.getSaveFileName(
            self,
            f"Export {format_name.upper()} report",
            f"premiere-security-report.{extension}",
            f"{format_name.upper()} files (*.{extension})",
        )
        if not path:
            return
        if not path.lower().endswith(f".{extension}"):
            path += f".{extension}"
        try:
            if format_name == "signed.json":
                content = json.dumps(ReportSigner().sign(self.report), indent=2)
            else:
                content = (
                    ReportFormatter.to_json(self.report)
                    if format_name == "json"
                    else ReportFormatter.to_csv(self.report)
                )
            Path(path).write_text(content, encoding="utf-8")
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "Export failed", str(exc))
            return
        QMessageBox.information(self, "Report exported", f"Saved to:\n{path}")


class ResultsDialog(QDialog):
    """A blocking result review window that is closed from its title-bar X."""

    def __init__(self, report, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Scan results")
        self.setModal(True)
        self.setWindowModality(Qt.WindowModality.ApplicationModal)
        self.setWindowFlags(
            Qt.WindowType.Dialog
            | Qt.WindowType.WindowTitleHint
            | Qt.WindowType.WindowCloseButtonHint
        )
        self.setMinimumSize(960, 650)
        self.resize(1100, 760)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.results_view = ResultsView(self)
        self.results_view.show_report(report)
        layout.addWidget(self.results_view)

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Escape:
            event.ignore()
            return
        super().keyPressEvent(event)

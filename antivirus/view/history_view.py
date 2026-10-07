"""Persistent scan-history view."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from antivirus.view.theme import status_color
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from antivirus.view.components import (
    EmptyState,
    configure_table,
    display_datetime,
    page_header,
    short_target,
)


class HistoryView(QWidget):
    history_changed = Signal()
    results_requested = Signal(object)

    def __init__(self, controller=None, parent=None):
        super().__init__(parent)
        self.controller = controller
        self._read_error = False
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 27, 30, 26)
        layout.setSpacing(16)

        heading = QHBoxLayout()
        heading.addWidget(
            page_header(
                "Scan history",
                "A local record of completed scans. No file contents are stored here.",
            ),
            1,
        )
        self.clear_selected_button = QPushButton("Clear selected", self)
        self.clear_selected_button.setProperty("variant", "danger")
        self.clear_selected_button.clicked.connect(self._clear_selected)
        self.clear_selected_button.setEnabled(False)
        heading.addWidget(self.clear_selected_button)
        self.clear_button = QPushButton("Clear all history", self)
        self.clear_button.setProperty("variant", "danger")
        self.clear_button.clicked.connect(self._clear_history)
        self.clear_button.setEnabled(False)
        heading.addWidget(self.clear_button)
        layout.addLayout(heading)

        self.table = QTableWidget(0, 8, self)
        self.table.setHorizontalHeaderLabels(
            [
                "Started",
                "Type",
                "Target",
                "Files",
                "Threats",
                "Duration",
                "Result",
                "View",
            ]
        )
        configure_table(self.table)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.itemSelectionChanged.connect(self._update_selection)
        self.table.setColumnWidth(0, 165)
        self.table.setColumnWidth(1, 80)
        self.table.setColumnWidth(2, 280)
        self.table.setColumnWidth(3, 65)
        self.table.setColumnWidth(4, 70)
        self.table.setColumnWidth(5, 80)
        self.table.setColumnWidth(6, 90)
        self.table.setColumnWidth(7, 100)
        self.table.horizontalHeader().setStretchLastSection(False)
        self.table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.Stretch
        )
        self.table.horizontalHeader().setSectionResizeMode(
            7, QHeaderView.ResizeMode.Fixed
        )
        self.table.hide()
        layout.addWidget(self.table, 1)

        self.empty_state = EmptyState(
            "○",
            "No scan history yet",
            "Completed scans will be saved here automatically.",
            self,
        )
        layout.addWidget(self.empty_state, 1)
        self.status = QLabel(
            "Showing the latest 100 scans. Ctrl-click or Shift-click to select entries; "
            "Ctrl+A selects the visible list.",
            self,
        )
        self.status.setWordWrap(True)
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        self.status.setProperty("role", "hint")
        layout.addWidget(self.status)

    def refresh(self):
        self._read_error = False
        self.table.setRowCount(0)
        try:
            records = self.controller.recent_scans() if self.controller else []
        except Exception:
            self._read_error = True
            self.empty_state.set_message(
                "History is unavailable",
                "Check access to the application data folder and try again.",
            )
            self.table.hide()
            self.empty_state.show()
            self.clear_button.setEnabled(False)
            self.clear_selected_button.setEnabled(False)
            return
        for record in records:
            row = self.table.rowCount()
            self.table.insertRow(row)
            duration = float(record.get("duration", 0) or 0)
            target = record.get("target", "")
            values = [
                display_datetime(record.get("started_at", "")),
                record.get("scan_type", "custom").title(),
                short_target(target),
                record.get("file_count", 0),
                record.get("threats_found", 0),
                f"{duration:.1f}s",
                record.get("status", "unknown").title(),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if column == 0:
                    item.setData(Qt.ItemDataRole.UserRole, record["id"])
                if column == 2:
                    item.setToolTip(target)
                if column == 6:
                    item.setForeground(QColor(status_color(record.get("status", ""))))
                self.table.setItem(row, column, item)
            results_button = QPushButton("Results", self.table)
            results_button.setProperty("compact", True)
            results_button.setCursor(Qt.CursorShape.PointingHandCursor)
            results_button.setAccessibleName(
                f"Open results for scan started {values[0]}"
            )
            results_button.clicked.connect(
                lambda _checked=False, saved_record=record: self.results_requested.emit(
                    saved_record
                )
            )
            self.table.setCellWidget(row, 7, results_button)
        has_records = bool(records)
        if not has_records:
            self.empty_state.set_message(
                "No scan history yet",
                "Completed scans will be saved here automatically.",
            )
        self.table.setVisible(has_records)
        self.empty_state.setVisible(not has_records)
        self.clear_button.setEnabled(has_records)
        self._update_selection()

    def _selected_ids(self):
        selected = []
        for index in self.table.selectionModel().selectedRows():
            item = self.table.item(index.row(), 0)
            if item and item.data(Qt.ItemDataRole.UserRole) is not None:
                selected.append(item.data(Qt.ItemDataRole.UserRole))
        return selected

    def _update_selection(self):
        selected = self._selected_ids()
        self.clear_selected_button.setEnabled(bool(selected) and not self._read_error)
        self.clear_selected_button.setText(
            f"Clear selected ({len(selected)})" if selected else "Clear selected"
        )

    def _clear_selected(self):
        selected = self._selected_ids()
        if not self.controller or not selected:
            return
        answer = QMessageBox.question(
            self,
            "Clear selected scan history",
            f"Remove {len(selected)} selected scan-history entries? "
            "Scanned files and quarantine contents remain in place.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if answer == QMessageBox.StandardButton.Yes:
            self._remove_history(lambda: self.controller.clear_selected(selected))

    def _remove_history(self, operation):
        try:
            removed = operation()
        except Exception:
            QMessageBox.warning(
                self,
                "History could not be cleared",
                "Check access to the application data folder and try again.",
            )
            return
        self.refresh()
        self.status.setText(
            f"Removed {removed} scan-history entries. New completed scans will be saved here."
        )
        self.history_changed.emit()

    def _clear_history(self):
        if not self.controller:
            return
        answer = QMessageBox.question(
            self,
            "Clear scan history",
            "Remove every saved scan-history entry, including older entries outside this list? "
            "Scanned files and quarantine contents remain in place.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self._remove_history(self.controller.clear_history)

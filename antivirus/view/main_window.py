"""Main Premiere Security application shell and page coordination."""

from __future__ import annotations

from PySide6.QtCore import Qt, QTimer, Signal, Slot
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from antivirus.controller.history_controller import HistoryController
from antivirus.controller.scan_controller import ScanController
from antivirus.model.scan_report import ScanReport
from antivirus.services.statistics_service import StatisticsService
from antivirus.view.branding import AppLogo
from antivirus.view.dashboard_view import DashboardView
from antivirus.view.history_view import HistoryView
from antivirus.view.results_view import ResultsDialog, ResultsView
from antivirus.view.scan_view import ScanView
from antivirus.view.settings_view import SettingsView
from antivirus.view.network_tab import NetworkMonitorTab
from antivirus.view.quarantine_view import QuarantineView
from antivirus.view.theme import apply_theme
from antivirus.services.download_watcher import DownloadWatcherService
from antivirus.services.scanner import Scanner
from antivirus.detection.detection_engine import DetectionEngine
from antivirus.utils.logging import get_logger

logger = get_logger(__name__)


class TopNavigation(QWidget):
    """Predictable top navigation that never shortens page names."""

    currentChanged = Signal(int)

    def __init__(self, page_names, page_indexes=None, parent=None):
        super().__init__(parent)
        self._current_index = -1
        self._buttons: list[QPushButton] = []
        self._page_indexes = tuple(
            range(len(page_names)) if page_indexes is None else page_indexes
        )
        if len(page_names) != len(self._page_indexes):
            raise ValueError("Navigation page names and indexes must match.")
        self._group = QButtonGroup(self)
        self._group.setExclusive(True)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        for button_index, (name, page_index) in enumerate(
            zip(page_names, self._page_indexes)
        ):
            button = QPushButton(name, self)
            button.setCheckable(True)
            button.setProperty("nav", True)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.clicked.connect(
                lambda _checked=False, page=page_index: self.setCurrentIndex(page)
            )
            self._group.addButton(button, button_index)
            self._buttons.append(button)
            layout.addWidget(button, 1)

    def setCurrentIndex(self, index: int) -> None:
        if index not in self._page_indexes:
            return
        self._buttons[self._page_indexes.index(index)].setChecked(True)
        if index == self._current_index:
            return
        self._current_index = index
        self.currentChanged.emit(index)

    def currentIndex(self) -> int:
        return self._current_index


class MainWindow(QMainWindow):
    """Application shell with a desktop-style top navigation bar."""

    PAGE_NAMES = (
        "Dashboard",
        "Scan",
        "Results",
        "Quarantine",
        "History",
        "Network",
        "Settings",
    )
    DASHBOARD, SCAN, RESULTS, QUARANTINE, HISTORY, NETWORK, SETTINGS = range(7)
    NAVIGATION_PAGES = (DASHBOARD, SCAN, QUARANTINE, HISTORY, NETWORK, SETTINGS)
    download_ready = Signal(object)
    monitor_failed = Signal(str)

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Premiere Security — Educational Antivirus")
        self.setMinimumSize(960, 640)
        self.resize(1180, 760)
        self.download_watcher = None
        self._closing = False
        self._close_timer = QTimer(self)
        self._close_timer.setInterval(100)
        self._close_timer.timeout.connect(self._finish_closing)

        self.scan_controller = ScanController()
        self.history_controller = HistoryController(self.scan_controller.repository)
        self.statistics_service = StatisticsService(
            scan_repo=self.scan_controller.repository
        )
        self._build_ui()
        self.download_ready.connect(self._download_result)
        self.monitor_failed.connect(self._monitor_failed)
        self._apply_saved_settings()
        self._refresh_dashboard()

    def _build_ui(self) -> None:
        root = QWidget(self)
        root.setObjectName("AppRoot")
        layout = QVBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        top_bar = QWidget(root)
        top_bar.setObjectName("TopBar")
        top_bar.setFixedHeight(126)
        top_layout = QVBoxLayout(top_bar)
        top_layout.setContentsMargins(22, 10, 22, 10)
        top_layout.setSpacing(8)
        branding = QHBoxLayout()
        branding.setSpacing(12)

        mark = AppLogo(top_bar)

        brand_text = QVBoxLayout()
        brand_text.setSpacing(0)
        brand_title = QLabel("Premiere Security", top_bar)
        brand_title.setProperty("role", "brandTitle")
        brand_subtitle = QLabel("Educational antivirus", top_bar)
        brand_subtitle.setProperty("role", "brandSubtitle")
        brand_text.addWidget(brand_title)
        brand_text.addWidget(brand_subtitle)

        self.theme_button = QPushButton(top_bar)
        self.theme_button.setProperty("themeToggle", True)
        self.theme_button.setCheckable(True)
        self.theme_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.theme_button.toggled.connect(self._set_theme)
        self._update_theme_button()

        self.navigation = TopNavigation(
            [self.PAGE_NAMES[index] for index in self.NAVIGATION_PAGES],
            self.NAVIGATION_PAGES,
            top_bar,
        )
        self.navigation.setObjectName("TopNavigation")

        branding.addWidget(mark)
        branding.addLayout(brand_text)
        branding.addWidget(self.theme_button)
        branding.addStretch()
        workspace_label = QLabel("Local scanning · Private quarantine", top_bar)
        workspace_label.setProperty("role", "brandSubtitle")
        branding.addWidget(workspace_label)
        top_layout.addLayout(branding)
        top_layout.addWidget(self.navigation)

        self.pages = QStackedWidget(root)
        self.pages.setObjectName("PageStack")
        self.dashboard_view = DashboardView(self.pages)
        self.scan_view = ScanView(
            self.scan_controller.scan_file,
            self.scan_controller.scan_directory,
            self.scan_controller.quick_scan,
            self.pages,
            scan_drives=self.scan_controller.scan_drives,
        )
        self.results_view = ResultsView(self.pages)
        self.quarantine_view = QuarantineView(parent=self.pages)
        self.history_view = HistoryView(self.history_controller, self.pages)
        self.settings_view = SettingsView(self.pages)
        self.network_tab = NetworkMonitorTab(self.pages)
        for page in (
            self.dashboard_view,
            self.scan_view,
            self.results_view,
            self.quarantine_view,
            self.history_view,
            self.network_tab,
            self.settings_view,
        ):
            scroll = QScrollArea(self.pages)
            scroll.setWidgetResizable(True)
            scroll.setFrameShape(QScrollArea.Shape.NoFrame)
            scroll.setWidget(page)
            self.pages.addWidget(scroll)

        layout.addWidget(top_bar)
        layout.addWidget(self.pages, 1)
        self.setCentralWidget(root)

        self.navigation.currentChanged.connect(self._navigate)
        self.navigation.setCurrentIndex(0)
        self.pages.setCurrentIndex(0)
        self.scan_view.scan_completed.connect(self._show_scan_result)
        self.scan_view.scan_started.connect(
            lambda: self.settings_view.setEnabled(False)
        )
        self.scan_view.scan_idle.connect(lambda: self.settings_view.setEnabled(True))
        self.scan_view.scan_started.connect(
            lambda: self.quarantine_view.setEnabled(False)
        )
        self.scan_view.scan_idle.connect(lambda: self.quarantine_view.setEnabled(True))
        self.scan_view.scan_started.connect(
            lambda: self.results_view.set_vault_busy(True)
        )
        self.scan_view.scan_idle.connect(
            lambda: self.results_view.set_vault_busy(self.quarantine_view.is_busy())
        )
        self.dashboard_view.start_scan.connect(self._quick_scan_from_dashboard)
        self.dashboard_view.open_history.connect(
            lambda: self.navigation.setCurrentIndex(self.HISTORY)
        )
        self.settings_view.setting_changed.connect(self._setting_changed)
        self.history_view.history_changed.connect(self._refresh_dashboard)
        self.history_view.results_requested.connect(self._show_history_result)
        self.results_view.quarantine_requested.connect(self._quarantine_result)
        self.quarantine_view.item_changed.connect(self.results_view.quarantine_changed)
        self.quarantine_view.busy_changed.connect(self._vault_busy_changed)

    def _set_theme(self, light_mode: bool) -> None:
        """Switch palettes without changing the user's current workspace."""

        application = QApplication.instance()
        if application is None:
            return
        apply_theme(application, "light" if light_mode else "dark")
        self._update_theme_button()
        self.centralWidget().update()

    def _update_theme_button(self) -> None:
        """Keep the compact brand control clear to sighted and screen-reader users."""

        if self.theme_button.isChecked():
            self.theme_button.setText("☀")
            self.theme_button.setAccessibleName("Light mode is active")
            self.theme_button.setToolTip("Light mode — click for dark mode")
        else:
            self.theme_button.setText("◐")
            self.theme_button.setAccessibleName("Dark mode is active")
            self.theme_button.setToolTip("Dark mode — click for light mode")

    def _vault_busy_changed(self, busy):
        self.results_view.set_vault_busy(busy or self.scan_view.is_scanning())
        self.scan_view.setEnabled(not busy)

    def _quarantine_result(self, result):
        if self.scan_view.is_scanning():
            self.statusBar().showMessage(
                "Wait for the scan to finish before isolating a file."
            )
            return
        results = result if isinstance(result, list) else [result]
        if self.quarantine_view.quarantine_results(results):
            self.navigation.setCurrentIndex(self.QUARANTINE)

    def _navigate(self, row):
        current_row = self.pages.currentIndex()
        if (
            current_row == self.SETTINGS
            and row != self.SETTINGS
            and self.settings_view.has_unsaved_changes()
            and not self.settings_view.resolve_unsaved_changes()
        ):
            self.navigation.blockSignals(True)
            self.navigation.setCurrentIndex(current_row)
            self.navigation.blockSignals(False)
            return
        self.pages.setCurrentIndex(row)
        self._page_changed(row)

    def _apply_saved_settings(self):
        for key, enabled in self.settings_view.values().items():
            self._setting_changed(key, enabled)
        states = self.scan_controller.scanner.detection_engine.get_engine_states()
        self.settings_view.update_availability(states)

    def _page_changed(self, row):
        if row == self.HISTORY:
            self.history_view.refresh()
        elif row == self.DASHBOARD:
            self._refresh_dashboard()
        elif row == self.SETTINGS:
            states = self.scan_controller.scanner.detection_engine.get_engine_states()
            self.settings_view.update_availability(states)
        elif row == self.QUARANTINE:
            self.quarantine_view.refresh()

    def _setting_changed(self, key, enabled):
        attribute = {
            "clamav_enabled": "clamav_enabled",
            "yara_enabled": "yara_enabled",
            "hash_detection_enabled": "hash_enabled",
            "virustotal_enabled": "virustotal_enabled",
        }.get(key)
        if attribute:
            setattr(self.scan_controller.scanner.detection_engine, attribute, enabled)
        elif key == "reduced_motion":
            self.scan_view.radar.set_reduced_motion(enabled)
        elif key == "download_monitor_enabled":
            self._set_download_monitor(enabled)
        if attribute and self.download_watcher and self.download_watcher.is_running:
            # The running watcher uses its own engine snapshot. Restart after it finishes.
            self.download_watcher.stop()
            self.settings_view.set_saved_value("download_monitor_enabled", False)
            self.statusBar().showMessage(
                "Download monitoring is stopping. Turn it off and on to apply the new engine settings."
            )
        if self.pages.currentIndex() == 0:
            self._refresh_dashboard()

    def _quick_scan_from_dashboard(self):
        if self.quarantine_view.is_busy():
            self.statusBar().showMessage(
                "Wait for the quarantine action to finish before starting a scan."
            )
            return
        self.navigation.setCurrentIndex(self.SCAN)
        QTimer.singleShot(100, self.scan_view.start_quick_scan)

    def _show_scan_result(self, result):
        if self._closing:
            return
        if hasattr(result, "results"):
            report = result
        else:
            report = ScanReport()
            report.add_result(result)
        self.results_view.show_report(report)
        self._show_results_dialog(report)
        if (
            self.pages.currentIndex() == self.SETTINGS
            and self.settings_view.has_unsaved_changes()
        ):
            self.statusBar().showMessage("Your scan results are ready for review.")
        else:
            self.statusBar().showMessage("Scan results were reviewed in the Results popup.")
        self._refresh_dashboard()

    def _show_history_result(self, record):
        report_data = record.get("report", {})
        report = (
            ScanReport.from_dict(report_data)
            if report_data
            else ScanReport.from_history_record(record)
        )
        self.results_view.show_report(report)
        self._show_results_dialog(report)

    def _show_results_dialog(self, report):
        """Keep scan results in a modal review window until its X is clicked."""

        dialog = ResultsDialog(report, self)
        dialog.exec()

    def _set_download_monitor(self, enabled):
        if not enabled:
            if self.download_watcher:
                self.download_watcher.stop()
            return
        try:
            engine = self.scan_controller.scanner.detection_engine
            watch_engine = DetectionEngine(
                hash_enabled=engine.hash_enabled,
                yara_enabled=engine.yara_enabled,
                clamav_enabled=engine.clamav_enabled,
                virustotal_enabled=engine.virustotal_enabled,
            )
            watch_controller = ScanController(
                Scanner(watch_engine), self.scan_controller.repository
            )

            def check_download(path):
                self.download_ready.emit(watch_controller.scan_file(path))

            if self.download_watcher and self.download_watcher.has_pending_work():
                raise RuntimeError(
                    "Download monitoring is still stopping. Try enabling it again shortly."
                )
            self.download_watcher = DownloadWatcherService(
                scanner_callback=check_download,
                error_callback=self.monitor_failed.emit,
            )
            self.download_watcher.start()
            self.statusBar().showMessage(
                "Download monitoring is on. Stable new files are checked; alerts do not block opening files."
            )
        except Exception as exc:
            self._monitor_failed(str(exc))

    @Slot(str)
    def _monitor_failed(self, message):
        if self.download_watcher:
            self.download_watcher.stop()
        self.settings_view.set_saved_value("download_monitor_enabled", False)
        self.statusBar().showMessage(f"Download monitoring is off: {message}")

    @Slot(object)
    def _download_result(self, result):
        if self._closing:
            return
        # Do not replace a manual scan's Results page with unsolicited background data.
        label = (
            "Suspicious download"
            if result.is_detected
            else (
                "No matches in download"
                if result.is_clean
                else "Download check incomplete"
            )
        )
        self.statusBar().showMessage(
            f"{label}: {result.file_path}. See History for the saved summary."
        )
        self._refresh_dashboard()

    def _refresh_dashboard(self):
        try:
            statistics = self.statistics_service.get_scan_statistics(hours=None)
            recent_scans = self.history_controller.recent_scans(limit=4)
            engine_states = (
                self.scan_controller.scanner.detection_engine.get_engine_states()
            )
            self.dashboard_view.update_dashboard(
                statistics, recent_scans, engine_states
            )
        except Exception:
            logger.exception("Dashboard could not load persisted statistics")
            self.dashboard_view.protection_title.setText("Scanner needs attention")
            self.dashboard_view.protection_detail.setText(
                "Protection details could not be loaded. Try reopening the application."
            )

    def _background_busy(self):
        return (
            self.scan_view.is_scanning()
            or self.network_tab.is_busy()
            or self.quarantine_view.is_busy()
            or bool(self.download_watcher and self.download_watcher.has_pending_work())
        )

    def _finish_closing(self):
        if not self._background_busy():
            self._close_timer.stop()
            self.close()

    def closeEvent(self, event):
        if self._closing:
            if self._background_busy():
                event.ignore()
            else:
                event.accept()
            return

        if self.settings_view.has_unsaved_changes():
            if not self.settings_view.resolve_unsaved_changes():
                event.ignore()
                return

        if self.scan_view.is_scanning():
            answer = QMessageBox.question(
                self,
                "Stop scan and close?",
                "A scan is still running. Do you want to stop it safely and close Premiere Security?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel,
            )
            if answer != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
        self._closing = True
        if self.download_watcher:
            self.download_watcher.stop()
        if self.scan_view.is_scanning():
            self.scan_view.cancel_active_scan(confirm=False)
        if self._background_busy():
            self.setEnabled(False)
            self.statusBar().showMessage("Finishing current checks before closing…")
            self._close_timer.start()
            event.ignore()
        else:
            event.accept()

"""Real offscreen Qt event-loop checks for radar and worker lifetimes."""

from time import monotonic
from threading import Event

from PySide6.QtTest import QTest
from PySide6.QtCore import QSettings

from antivirus.model.scan_report import ScanReport
from antivirus.model.scan_result import ScanResult
from antivirus.model.scan_status import ScanStatus
from antivirus.view.scan_view import ScanView
from antivirus.view.results_view import ResultsDialog, ResultsView
from antivirus.view.main_window import MainWindow


def until(qapp, predicate, timeout=5):
    deadline = monotonic() + timeout
    while not predicate() and monotonic() < deadline:
        qapp.processEvents()
        QTest.qWait(10)
    assert predicate(), "Qt workflow did not finish within the deadline"


def test_radar_tracks_scan_lifecycle_and_results_are_emitted_after_idle(qapp):
    release = Event()

    def scan(path):
        release.wait(timeout=2)
        return ScanResult(path)

    view = ScanView(scan_file=scan)
    view.resize(1100, 640)
    view.show()
    qapp.processEvents()
    received = []
    view.scan_completed.connect(
        lambda result: received.append((result, view.is_scanning()))
    )
    view._start_scan(scan, "safe.txt", "File scan")
    assert view.radar.state == "scanning"
    assert view.radar._timer.isActive()
    assert not view.select_file_button.isEnabled()
    view.radar.set_reduced_motion(True)
    assert not view.radar._timer.isActive()
    release.set()
    until(qapp, lambda: not view.is_scanning())
    assert view.radar.state == "complete"
    assert not view.radar._timer.isActive()
    assert view.select_file_button.isEnabled()
    assert len(received) == 1
    assert received[0][1] is False
    view.close()


def test_cancelled_scan_keeps_partial_results_and_stops_radar(qapp):
    def folder(path, progress_callback, cancel_check):
        report = ScanReport()
        report.add_result(ScanResult("one.txt"))
        deadline = monotonic() + 2
        while not cancel_check() and monotonic() < deadline:
            Event().wait(0.01)
        report.cancelled = cancel_check()
        return report

    view = ScanView(scan_directory=folder)
    view.show()
    received = []
    view.scan_completed.connect(received.append)
    view._start_scan(folder, "folder", "Folder scan", True)
    view.cancel_active_scan(confirm=False)
    until(qapp, lambda: not view.is_scanning())
    assert view.radar.state == "cancelled"
    assert received[0].cancelled
    assert received[0].total_files == 1
    view.close()


def test_failed_scan_stops_radar_and_unlocks_controls(qapp):
    def broken(path):
        raise RuntimeError("cannot read target")

    view = ScanView(scan_file=broken)
    view.show()
    view._start_scan(broken, "target", "File scan")
    until(qapp, lambda: not view.is_scanning())
    assert view.radar.state == "error"
    assert view.quick_scan_button.isEnabled()
    assert "cannot read" in view.status_label.text()
    view.close()


def test_skipped_results_filter_and_exports(qapp):
    view = ResultsView()
    report = ScanReport(cancelled=True)
    report.add_result(ScanResult("safe", ScanStatus.CLEAN))
    report.add_result(ScanResult("big", ScanStatus.SKIPPED))
    view.show_report(report)
    assert view.error_card.value_label.text() == "1"
    assert "Cancelled" in view.summary.text()
    view.filter_combo.setCurrentIndex(4)
    assert view.table.rowCount() == 1
    assert view.table.item(0, 0).text() == "big"
    assert view.export_signed_button.isEnabled()
    view.close()


def test_results_dialog_is_modal_and_populates_saved_report(qapp):
    report = ScanReport()
    report.add_result(ScanResult("safe.txt"))
    dialog = ResultsDialog(report)
    assert dialog.isModal()
    assert dialog.results_view.report is report
    assert dialog.results_view.table.rowCount() == 1
    dialog.close()


def test_navigation_uses_named_page_indices_and_keeps_settings_preferences(qapp):
    settings = QSettings("IAS", "PremiereSecurity")
    settings.clear()
    window = MainWindow()
    window.show()
    assert "Results" not in [
        button.text() for button in window.navigation._buttons
    ]
    for index in window.NAVIGATION_PAGES:
        window.navigation.setCurrentIndex(index)
        assert window.pages.currentIndex() == index
    saved = window.settings_view.values()
    window.settings_view.update_availability({})
    assert window.settings_view.values() == saved
    assert not window.settings_view.has_unsaved_changes()
    assert window.network_tab.table.columnCount() == 5
    window.close()
    settings.clear()


def test_large_result_set_is_paged_and_searchable_without_losing_exports(qapp):
    from antivirus.services.report_formatter import ReportFormatter

    view = ResultsView()
    report = ScanReport()
    for i in range(620):
        report.add_result(ScanResult(f"file-{i:04}.txt"))
    view.show_report(report)
    assert view.table.rowCount() == 250
    assert view.next_button.isEnabled()
    view._change_page(1)
    assert view.table.item(0, 0).text() == "file-0250.txt"
    view.search_box.setText("file-0619")
    assert view.table.rowCount() == 1
    assert view.table.item(0, 0).text() == "file-0619.txt"
    assert len(ReportFormatter.to_dict(report)["results"]) == 620
    view.close()

#!/usr/bin/env python3
"""
ZapGuard - ZAP Vulnerability Fix Verification Tool
Professional GUI with modern UI/UX design.
"""

import sys
import re
import ctypes
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple
from urllib.parse import urlparse
import threading

# Set Windows taskbar icon - must be done before QApplication
if sys.platform == 'win32':
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID('zapguard.gui.1')

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QFileDialog, QProgressBar,
    QTableWidget, QTableWidgetItem, QHeaderView, QFrame,
    QTextEdit, QMessageBox, QGraphicsDropShadowEffect, QSizePolicy
)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QFont, QColor, QIcon, QPixmap, QPainter, QBrush, QPen, QLinearGradient, QPainterPath

from .models import Alert, Instance, TestResult, TestStatus, RiskLevel
from .parsers import parse_zap_report
from .http_client import HTTPClient
from .vulnerability_tests import get_test_class


def is_valid_url(url: str) -> bool:
    """Validate URL format."""
    if not url:
        return False
    try:
        result = urlparse(url)
        if result.scheme not in ('http', 'https'):
            return False
        if not result.netloc:
            return False
        netloc = result.netloc.split(':')[0]
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$'
        return bool(re.match(ip_pattern, netloc) or re.match(domain_pattern, netloc))
    except Exception:
        return False


def get_status_color(status: TestStatus) -> str:
    return {
        TestStatus.PASS: "#10b981",
        TestStatus.FAIL: "#ef4444",
        TestStatus.NOT_TESTABLE: "#f59e0b",
        TestStatus.ERROR: "#8b5cf6"
    }.get(status, "#6b7280")


def get_risk_color(risk: RiskLevel) -> str:
    return {
        RiskLevel.HIGH: "#ef4444",
        RiskLevel.MEDIUM: "#f59e0b",
        RiskLevel.LOW: "#eab308",
        RiskLevel.INFORMATIONAL: "#3b82f6"
    }.get(risk, "#6b7280")


def create_app_icon() -> QIcon:
    """Create application icon programmatically."""
    icon = QIcon()
    for size in [16, 32, 48, 64, 128, 256]:
        pixmap = QPixmap(size, size)
        pixmap.fill(Qt.transparent)

        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.Antialiasing, True)

        # Scale factor
        s = size / 64.0

        # Shield gradient
        shield_grad = QLinearGradient(32 * s, 4 * s, 32 * s, 60 * s)
        shield_grad.setColorAt(0, QColor("#3b82f6"))
        shield_grad.setColorAt(1, QColor("#1d4ed8"))

        # Draw shield path
        shield = QPainterPath()
        shield.moveTo(32 * s, 4 * s)
        shield.lineTo(56 * s, 12 * s)
        shield.lineTo(56 * s, 28 * s)
        shield.cubicTo(56 * s, 44 * s, 44 * s, 54 * s, 32 * s, 60 * s)
        shield.cubicTo(20 * s, 54 * s, 8 * s, 44 * s, 8 * s, 28 * s)
        shield.lineTo(8 * s, 12 * s)
        shield.closeSubpath()

        # Fill shield
        painter.setPen(QPen(QColor("#1e40af"), 2 * s))
        painter.setBrush(QBrush(shield_grad))
        painter.drawPath(shield)

        # Draw checkmark
        check_grad = QLinearGradient(24 * s, 24 * s, 42 * s, 38 * s)
        check_grad.setColorAt(0, QColor("#22c55e"))
        check_grad.setColorAt(1, QColor("#16a34a"))

        pen = QPen(QBrush(check_grad), 5 * s, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin)
        painter.setPen(pen)
        painter.setBrush(Qt.NoBrush)

        check = QPainterPath()
        check.moveTo(22 * s, 32 * s)
        check.lineTo(29 * s, 40 * s)
        check.lineTo(42 * s, 24 * s)
        painter.drawPath(check)

        painter.end()
        icon.addPixmap(pixmap)

    return icon


# Theme definitions
THEMES = {
    'dark': {
        'bg_primary': '#0f172a',
        'bg_secondary': '#1e293b',
        'bg_input': '#1f2937',
        'border': '#334155',
        'text_primary': '#f1f5f9',
        'text_secondary': '#94a3b8',
        'text_muted': '#64748b',
        'accent': '#3b82f6',
        'card_gradient_start': '#1f2937',
        'card_gradient_end': '#111827',
    },
    'light': {
        'bg_primary': '#f8fafc',
        'bg_secondary': '#ffffff',
        'bg_input': '#f1f5f9',
        'border': '#e2e8f0',
        'text_primary': '#1e293b',
        'text_secondary': '#475569',
        'text_muted': '#64748b',
        'accent': '#3b82f6',
        'card_gradient_start': '#ffffff',
        'card_gradient_end': '#f8fafc',
    }
}


class ValidationWorker(QThread):
    """Background worker for running validation tests."""
    progress = Signal(int, int, str)
    result_ready = Signal(object)
    log_message = Signal(str)
    finished_all = Signal(list)

    def __init__(self, alerts: List[Alert], base_url: str, timeout: int = 20, max_workers: int = 10):
        super().__init__()
        self.alerts = alerts
        self.base_url = base_url
        self.timeout = timeout
        self.max_workers = max_workers
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def is_stopped(self):
        return self._stop_event.is_set()

    def run(self):
        client = HTTPClient(self.base_url, self.timeout)
        results = []

        tasks: List[Tuple[Alert, Instance]] = []
        for alert in self.alerts:
            for instance in alert.instances:
                tasks.append((alert, instance))

        total = len(tasks)
        self.log_message.emit(f"Starting validation of {total} endpoints...")

        completed = 0
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_task = {}
            for alert, instance in tasks:
                if self.is_stopped():
                    break
                future = executor.submit(self._test_instance, client, alert, instance)
                future_to_task[future] = (alert, instance)

            for future in as_completed(future_to_task):
                if self.is_stopped():
                    executor.shutdown(wait=False, cancel_futures=True)
                    self.log_message.emit("Validation cancelled.")
                    break

                try:
                    result = future.result(timeout=1)
                    if result and not self.is_stopped():
                        results.append(result)
                        completed += 1
                        alert, instance = future_to_task[future]
                        self.progress.emit(completed, total, instance.url[:50])
                        self.result_ready.emit(result)
                except Exception as e:
                    if not self.is_stopped():
                        self.log_message.emit(f"Error: {str(e)[:80]}")

        self.finished_all.emit(results)

    def _test_instance(self, client: HTTPClient, alert: Alert, instance: Instance) -> TestResult:
        if self.is_stopped():
            return None
        test_class = get_test_class(alert.plugin_id)
        test = test_class(client)
        try:
            return test.test(alert, instance)
        except Exception as e:
            return TestResult(
                alert_name=alert.name,
                plugin_id=alert.plugin_id,
                risk_level=alert.risk_level,
                status=TestStatus.ERROR,
                endpoint=instance.url,
                method=instance.method,
                details=f"Error: {str(e)}"
            )


class StatCard(QFrame):
    """Minimal stat card."""

    def __init__(self, title: str, value: str = "0", color: str = "#3b82f6"):
        super().__init__()
        self.color = color
        self.title = title
        self._dark_mode = True

        self.setMinimumSize(120, 90)
        self.setMaximumSize(160, 110)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(4)

        self.value_label = QLabel(value)
        self.value_label.setFont(QFont("Segoe UI", 28, QFont.Bold))
        layout.addWidget(self.value_label)

        self.title_label = QLabel(title)
        self.title_label.setFont(QFont("Segoe UI", 9))
        layout.addWidget(self.title_label)

        layout.addStretch()
        self._apply_style()

    def _apply_style(self):
        theme = THEMES['dark'] if self._dark_mode else THEMES['light']
        self.setStyleSheet(f"""
            StatCard {{
                background: {theme['bg_secondary']};
                border-radius: 10px;
                border-left: 3px solid {self.color};
            }}
        """)
        self.value_label.setStyleSheet(f"color: {self.color}; background: transparent;")
        title_color = "#475569" if not self._dark_mode else theme['text_muted']
        title_weight = "600" if not self._dark_mode else "normal"
        self.title_label.setStyleSheet(f"color: {title_color}; background: transparent; font-weight: {title_weight};")

    def set_value(self, value: str):
        self.value_label.setText(value)

    def set_dark_mode(self, dark: bool):
        self._dark_mode = dark
        self._apply_style()


class ZapGuardWindow(QMainWindow):
    """Main application window."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("ZapGuard")
        self.setMinimumSize(1200, 800)
        self.alerts = []
        self.results = []
        self.worker = None
        self.start_time = None
        self.is_running = False
        self._dark_mode = True

        self._setup_ui()
        self._apply_theme()

    def _apply_theme(self):
        theme = THEMES['dark'] if self._dark_mode else THEMES['light']

        self.setStyleSheet(f"""
            QMainWindow {{
                background: {theme['bg_primary']};
            }}
            QMainWindow > QWidget {{
                background: {theme['bg_primary']};
            }}
            QWidget {{
                color: {theme['text_primary']};
            }}
            QScrollBar:vertical {{
                background: {theme['bg_secondary']};
                width: 8px;
                border-radius: 4px;
            }}
            QScrollBar::handle:vertical {{
                background: {theme['text_muted']};
                border-radius: 4px;
                min-height: 30px;
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                height: 0;
            }}
        """)

        # Ensure central widget has correct background
        if self.centralWidget():
            self.centralWidget().setStyleSheet(f"background: {theme['bg_primary']};")

        # Update input fields
        input_style_valid = f"""
            QLineEdit {{
                background: {theme['bg_input']};
                border: 1px solid {theme['border']};
                border-radius: 6px;
                padding: 0 12px;
                color: {theme['text_primary']};
                selection-background-color: {theme['accent']};
            }}
            QLineEdit:focus {{
                border: 2px solid {theme['accent']};
            }}
            QLineEdit::placeholder {{
                color: {theme['text_muted']};
            }}
        """
        self.url_input.setStyleSheet(input_style_valid)
        self.report_input.setStyleSheet(input_style_valid)
        self.output_input.setStyleSheet(input_style_valid)

        # Update labels - bold in light mode for better visibility
        label_weight = "600" if not self._dark_mode else "normal"
        for label in [self.url_label, self.report_label, self.output_label]:
            label.setStyleSheet(f"color: {theme['text_secondary']}; font-weight: {label_weight};")

        # Update section titles
        self.results_title.setStyleSheet(f"color: {theme['text_primary']}; font-weight: bold;")
        self.log_title.setStyleSheet(f"color: {theme['text_secondary']}; font-weight: {label_weight};")

        # Update table
        table_font_weight = "500" if not self._dark_mode else "normal"
        header_color = "#1e293b" if not self._dark_mode else theme['text_secondary']
        self.results_table.setStyleSheet(f"""
            QTableWidget {{
                background: transparent;
                border: none;
                color: {theme['text_primary']};
                gridline-color: {theme['border']};
                font-weight: {table_font_weight};
            }}
            QTableWidget::item {{
                padding: 8px 12px;
                border-bottom: 1px solid {theme['border']};
            }}
            QTableWidget::item:selected {{
                background: {theme['accent']}40;
            }}
            QHeaderView::section {{
                background: {theme['bg_secondary']};
                color: {header_color};
                padding: 10px 12px;
                border: none;
                border-bottom: 1px solid {theme['border']};
                font-weight: 700;
                font-size: 11px;
            }}
        """)

        # Update log
        self.log_text.setStyleSheet(f"""
            QTextEdit {{
                background: {theme['bg_input']};
                border: none;
                border-radius: 6px;
                color: {theme['text_muted']};
                padding: 8px;
            }}
        """)

        # Update progress bar
        self.progress_bar.setStyleSheet(f"""
            QProgressBar {{
                background: {theme['bg_input']};
                border: none;
                border-radius: 3px;
                height: 6px;
            }}
            QProgressBar::chunk {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #3b82f6, stop:1 #8b5cf6);
                border-radius: 3px;
            }}
        """)

        # Update stat cards
        for card in self.stat_cards:
            card.set_dark_mode(self._dark_mode)

        # Update theme button
        self.theme_btn.setText("Light" if self._dark_mode else "Dark")
        if self._dark_mode:
            self.theme_btn.setStyleSheet("""
                QPushButton {
                    background: #374151;
                    color: #e5e7eb;
                    border: none;
                    border-radius: 14px;
                    font-weight: 500;
                }
                QPushButton:hover {
                    background: #4b5563;
                }
            """)
        else:
            self.theme_btn.setStyleSheet("""
                QPushButton {
                    background: #e2e8f0;
                    color: #1e293b;
                    border: none;
                    border-radius: 14px;
                    font-weight: 600;
                }
                QPushButton:hover {
                    background: #cbd5e1;
                }
            """)

        # Update status colors
        self._set_status(self.status_text.text(),
                        "#22c55e" if "Ready" in self.status_text.text() or "Passed" in self.status_text.text()
                        else "#ef4444" if "Issue" in self.status_text.text() or "Error" in self.status_text.text()
                        else "#3b82f6")

    def _toggle_theme(self):
        self._dark_mode = not self._dark_mode
        self._apply_theme()

    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(32, 24, 32, 24)
        main_layout.setSpacing(24)

        # ===== HEADER =====
        header = QHBoxLayout()

        title_area = QVBoxLayout()
        title_area.setSpacing(0)

        logo = QLabel("ZapGuard")
        logo.setFont(QFont("Segoe UI", 26, QFont.Bold))
        logo.setStyleSheet("color: #3b82f6;")
        title_area.addWidget(logo)

        tagline = QLabel("Vulnerability Fix Verification")
        tagline.setFont(QFont("Segoe UI", 10))
        tagline.setStyleSheet("color: #64748b;")
        title_area.addWidget(tagline)

        header.addLayout(title_area)
        header.addStretch()

        # Status
        self.status_indicator = QFrame()
        self.status_indicator.setFixedSize(10, 10)
        self.status_indicator.setStyleSheet("background: #22c55e; border-radius: 5px;")
        header.addWidget(self.status_indicator)

        self.status_text = QLabel("Ready")
        self.status_text.setFont(QFont("Segoe UI", 10, QFont.Medium))
        self.status_text.setStyleSheet("color: #22c55e;")
        header.addWidget(self.status_text)

        header.addSpacing(20)

        # Theme toggle
        self.theme_btn = QPushButton("Light")
        self.theme_btn.setFont(QFont("Segoe UI", 9))
        self.theme_btn.setCursor(Qt.PointingHandCursor)
        self.theme_btn.setFixedSize(60, 28)
        self.theme_btn.clicked.connect(self._toggle_theme)
        self.theme_btn.setStyleSheet("""
            QPushButton {
                background: #374151;
                color: #e5e7eb;
                border: none;
                border-radius: 14px;
                font-weight: 500;
            }
            QPushButton:hover {
                background: #4b5563;
            }
        """)
        header.addWidget(self.theme_btn)

        main_layout.addLayout(header)

        # ===== CONFIGURATION =====
        config_layout = QVBoxLayout()
        config_layout.setSpacing(12)

        # Target URL
        url_row = QHBoxLayout()
        self.url_label = QLabel("Target URL")
        self.url_label.setFixedWidth(90)
        self.url_label.setFont(QFont("Segoe UI", 10))
        url_row.addWidget(self.url_label)

        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("http://example.com or http://10.0.0.1")
        self.url_input.setFont(QFont("Segoe UI", 10))
        self.url_input.setFixedHeight(38)
        self.url_input.textChanged.connect(self._validate_url)
        url_row.addWidget(self.url_input)

        self.url_status = QLabel("")
        self.url_status.setFixedWidth(60)
        self.url_status.setFont(QFont("Segoe UI", 9))
        url_row.addWidget(self.url_status)

        config_layout.addLayout(url_row)

        # ZAP Report
        report_row = QHBoxLayout()
        self.report_label = QLabel("ZAP Report")
        self.report_label.setFixedWidth(90)
        self.report_label.setFont(QFont("Segoe UI", 10))
        report_row.addWidget(self.report_label)

        self.report_input = QLineEdit()
        self.report_input.setPlaceholderText("Select ZAP report (.html, .xml, .json)")
        self.report_input.setFont(QFont("Segoe UI", 10))
        self.report_input.setFixedHeight(38)
        report_row.addWidget(self.report_input)

        browse_btn = QPushButton("Browse")
        browse_btn.setFont(QFont("Segoe UI", 9, QFont.Medium))
        browse_btn.setCursor(Qt.PointingHandCursor)
        browse_btn.setFixedSize(80, 38)
        browse_btn.clicked.connect(self._browse_report)
        browse_btn.setStyleSheet("""
            QPushButton {
                background: #374151;
                color: #e5e7eb;
                border: none;
                border-radius: 6px;
            }
            QPushButton:hover { background: #4b5563; }
        """)
        report_row.addWidget(browse_btn)

        config_layout.addLayout(report_row)

        # Output Directory
        output_row = QHBoxLayout()
        self.output_label = QLabel("Output Dir")
        self.output_label.setFixedWidth(90)
        self.output_label.setFont(QFont("Segoe UI", 10))
        output_row.addWidget(self.output_label)

        self.output_input = QLineEdit()
        self.output_input.setPlaceholderText("Output directory for reports")
        self.output_input.setFont(QFont("Segoe UI", 10))
        self.output_input.setFixedHeight(38)
        output_row.addWidget(self.output_input)

        output_btn = QPushButton("Browse")
        output_btn.setFont(QFont("Segoe UI", 9, QFont.Medium))
        output_btn.setCursor(Qt.PointingHandCursor)
        output_btn.setFixedSize(80, 38)
        output_btn.clicked.connect(self._browse_output)
        output_btn.setStyleSheet("""
            QPushButton {
                background: #374151;
                color: #e5e7eb;
                border: none;
                border-radius: 6px;
            }
            QPushButton:hover { background: #4b5563; }
        """)
        output_row.addWidget(output_btn)

        config_layout.addLayout(output_row)
        main_layout.addLayout(config_layout)

        # ===== ACTION BUTTONS =====
        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)

        self.start_btn = QPushButton("Start Validation")
        self.start_btn.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.start_btn.setCursor(Qt.PointingHandCursor)
        self.start_btn.setFixedHeight(40)
        self.start_btn.setMinimumWidth(140)
        self.start_btn.clicked.connect(self._start_validation)
        self.start_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #3b82f6, stop:1 #2563eb);
                color: white;
                border: none;
                border-radius: 8px;
                padding: 0 20px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #60a5fa, stop:1 #3b82f6);
            }
            QPushButton:disabled { background: #374151; color: #6b7280; }
        """)
        btn_row.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setFont(QFont("Segoe UI", 10, QFont.Medium))
        self.stop_btn.setCursor(Qt.PointingHandCursor)
        self.stop_btn.setFixedSize(80, 40)
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop_validation)
        self.stop_btn.setStyleSheet("""
            QPushButton {
                background: #dc2626;
                color: white;
                border: none;
                border-radius: 8px;
            }
            QPushButton:hover { background: #ef4444; }
            QPushButton:disabled { background: #374151; color: #6b7280; }
        """)
        btn_row.addWidget(self.stop_btn)

        self.clear_btn = QPushButton("Clear")
        self.clear_btn.setFont(QFont("Segoe UI", 10, QFont.Medium))
        self.clear_btn.setCursor(Qt.PointingHandCursor)
        self.clear_btn.setFixedSize(80, 40)
        self.clear_btn.clicked.connect(self._clear_results)
        self.clear_btn.setStyleSheet("""
            QPushButton {
                background: #374151;
                color: #e5e7eb;
                border: none;
                border-radius: 8px;
            }
            QPushButton:hover { background: #4b5563; }
        """)
        btn_row.addWidget(self.clear_btn)

        btn_row.addStretch()

        self.export_html_btn = QPushButton("Export HTML")
        self.export_html_btn.setFont(QFont("Segoe UI", 10, QFont.Medium))
        self.export_html_btn.setCursor(Qt.PointingHandCursor)
        self.export_html_btn.setFixedHeight(40)
        self.export_html_btn.setMinimumWidth(110)
        self.export_html_btn.setEnabled(False)
        self.export_html_btn.clicked.connect(self._export_html)
        self.export_html_btn.setStyleSheet("""
            QPushButton {
                background: #059669;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 0 16px;
            }
            QPushButton:hover { background: #10b981; }
            QPushButton:disabled { background: #374151; color: #6b7280; }
        """)
        btn_row.addWidget(self.export_html_btn)

        self.export_csv_btn = QPushButton("Export CSV")
        self.export_csv_btn.setFont(QFont("Segoe UI", 10, QFont.Medium))
        self.export_csv_btn.setCursor(Qt.PointingHandCursor)
        self.export_csv_btn.setFixedHeight(40)
        self.export_csv_btn.setMinimumWidth(100)
        self.export_csv_btn.setEnabled(False)
        self.export_csv_btn.clicked.connect(self._export_csv)
        self.export_csv_btn.setStyleSheet("""
            QPushButton {
                background: #374151;
                color: #e5e7eb;
                border: none;
                border-radius: 8px;
                padding: 0 16px;
            }
            QPushButton:hover { background: #4b5563; }
            QPushButton:disabled { background: #1f2937; color: #4b5563; }
        """)
        btn_row.addWidget(self.export_csv_btn)

        main_layout.addLayout(btn_row)

        # ===== PROGRESS =====
        progress_row = QHBoxLayout()
        progress_row.setSpacing(12)

        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedHeight(6)
        self.progress_bar.setTextVisible(False)
        progress_row.addWidget(self.progress_bar, 1)

        self.progress_text = QLabel("0%")
        self.progress_text.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.progress_text.setStyleSheet("color: #3b82f6;")
        self.progress_text.setFixedWidth(45)
        progress_row.addWidget(self.progress_text)

        self.progress_detail = QLabel("")
        self.progress_detail.setFont(QFont("Segoe UI", 9))
        self.progress_detail.setStyleSheet("color: #64748b;")
        progress_row.addWidget(self.progress_detail)

        main_layout.addLayout(progress_row)

        # ===== STATS =====
        stats_row = QHBoxLayout()
        stats_row.setSpacing(12)

        self.card_total = StatCard("Total", "0", "#3b82f6")
        self.card_passed = StatCard("Passed", "0", "#10b981")
        self.card_failed = StatCard("Failed", "0", "#ef4444")
        self.card_skipped = StatCard("Skipped", "0", "#f59e0b")
        self.card_errors = StatCard("Errors", "0", "#8b5cf6")
        self.card_rate = StatCard("Pass Rate", "0%", "#06b6d4")

        self.stat_cards = [self.card_total, self.card_passed, self.card_failed,
                          self.card_skipped, self.card_errors, self.card_rate]

        for card in self.stat_cards:
            card.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
            stats_row.addWidget(card)

        stats_row.addStretch()
        main_layout.addLayout(stats_row)

        # ===== RESULTS =====
        results_header = QHBoxLayout()
        self.results_title = QLabel("Results")
        self.results_title.setFont(QFont("Segoe UI", 12, QFont.Bold))
        results_header.addWidget(self.results_title)

        results_header.addStretch()

        self.results_count = QLabel("0 items")
        self.results_count.setFont(QFont("Segoe UI", 10))
        self.results_count.setStyleSheet("color: #64748b;")
        results_header.addWidget(self.results_count)

        main_layout.addLayout(results_header)

        self.results_table = QTableWidget()
        self.results_table.setColumnCount(6)
        self.results_table.setHorizontalHeaderLabels([
            "Status", "Risk", "Vulnerability", "Method", "Endpoint", "Details"
        ])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.results_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.results_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.results_table.setShowGrid(False)
        self.results_table.verticalHeader().setVisible(False)
        self.results_table.setAlternatingRowColors(False)
        main_layout.addWidget(self.results_table, 1)

        # ===== LOG =====
        log_header = QHBoxLayout()
        self.log_title = QLabel("Activity Log")
        self.log_title.setFont(QFont("Segoe UI", 10))
        log_header.addWidget(self.log_title)
        log_header.addStretch()
        main_layout.addLayout(log_header)

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Consolas", 9))
        self.log_text.setFixedHeight(80)
        main_layout.addWidget(self.log_text)

        # Initial validation
        self._validate_url(self.url_input.text())

    def _validate_url(self, text: str):
        if not text.strip():
            self.url_status.setText("")
            return
        if is_valid_url(text.strip()):
            self.url_status.setText("Valid")
            self.url_status.setStyleSheet("color: #10b981;")
        else:
            self.url_status.setText("Invalid")
            self.url_status.setStyleSheet("color: #ef4444;")

    def _browse_report(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select ZAP Report", str(Path.home() / "Downloads"),
            "ZAP Reports (*.html *.htm *.xml *.json);;All Files (*)"
        )
        if path:
            self.report_input.setText(path)

    def _browse_output(self):
        path = QFileDialog.getExistingDirectory(self, "Select Output Directory", self.output_input.text())
        if path:
            self.output_input.setText(path)

    def _log(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_text.append(f"[{ts}] {msg}")
        self.log_text.verticalScrollBar().setValue(self.log_text.verticalScrollBar().maximum())

    def _set_status(self, text: str, color: str = "#22c55e"):
        self.status_text.setText(text)
        self.status_text.setStyleSheet(f"color: {color};")
        self.status_indicator.setStyleSheet(f"background: {color}; border-radius: 5px;")

    def _start_validation(self):
        if self.is_running:
            return

        url = self.url_input.text().strip()
        report = self.report_input.text().strip()

        if not url:
            QMessageBox.warning(self, "Error", "Please enter a target URL.")
            return
        if not is_valid_url(url):
            QMessageBox.warning(self, "Error", "Invalid URL format.")
            return
        if not report or not Path(report).exists():
            QMessageBox.warning(self, "Error", "Please select a valid ZAP report file.")
            return

        self._clear_results()
        self._log("Parsing ZAP report...")
        self._set_status("Parsing...", "#f59e0b")
        QApplication.processEvents()

        try:
            self.alerts = parse_zap_report(report)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to parse report:\n{e}")
            self._set_status("Error", "#ef4444")
            return

        if not self.alerts:
            QMessageBox.warning(self, "Warning", "No alerts found in the report.")
            self._set_status("Ready", "#22c55e")
            return

        total = sum(len(a.instances) for a in self.alerts)
        self._log(f"Found {len(self.alerts)} alerts with {total} instances")

        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(0)
        self.progress_text.setText("0%")

        self.is_running = True
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.clear_btn.setEnabled(False)
        self.export_html_btn.setEnabled(False)
        self.export_csv_btn.setEnabled(False)
        self._set_status("Running", "#3b82f6")
        self.start_time = datetime.now()

        self.worker = ValidationWorker(self.alerts, url)
        self.worker.progress.connect(self._on_progress)
        self.worker.result_ready.connect(self._on_result)
        self.worker.log_message.connect(self._log)
        self.worker.finished_all.connect(self._on_finished)
        self.worker.start()

    def _stop_validation(self):
        if self.worker and self.is_running:
            self._log("Stopping...")
            self._set_status("Stopping...", "#f59e0b")
            self.worker.stop()
            self.stop_btn.setEnabled(False)

    def _clear_results(self):
        self.results = []
        self.alerts = []
        self.results_table.setRowCount(0)
        self.progress_bar.setValue(0)
        self.progress_bar.setMaximum(100)
        self.progress_text.setText("0%")
        self.progress_detail.setText("")
        self.results_count.setText("0 items")
        self._update_stats()
        self._set_status("Ready", "#22c55e")

    def _on_progress(self, current: int, total: int, endpoint: str):
        self.progress_bar.setValue(current)
        pct = int((current / total) * 100) if total else 0
        self.progress_text.setText(f"{pct}%")
        self.progress_detail.setText(endpoint[:50] + "..." if len(endpoint) > 50 else endpoint)

    def _on_result(self, result: TestResult):
        if result:
            self.results.append(result)
            self._add_row(result)
            self._update_stats()

    def _add_row(self, r: TestResult):
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)

        status = QTableWidgetItem(r.status.value)
        status.setForeground(QColor(get_status_color(r.status)))
        status.setFont(QFont("Segoe UI", 9, QFont.Bold))
        self.results_table.setItem(row, 0, status)

        risk = QTableWidgetItem(r.risk_level.name)
        risk.setForeground(QColor(get_risk_color(r.risk_level)))
        self.results_table.setItem(row, 1, risk)

        self.results_table.setItem(row, 2, QTableWidgetItem(r.alert_name))
        self.results_table.setItem(row, 3, QTableWidgetItem(r.method))

        ep = QTableWidgetItem(r.endpoint)
        ep.setFont(QFont("Consolas", 9))
        self.results_table.setItem(row, 4, ep)

        det = QTableWidgetItem(r.details[:60] if r.details else "")
        det.setForeground(QColor("#64748b"))
        self.results_table.setItem(row, 5, det)

        self.results_count.setText(f"{row + 1} items")

    def _update_stats(self):
        total = len(self.results)
        passed = sum(1 for r in self.results if r.status == TestStatus.PASS)
        failed = sum(1 for r in self.results if r.status == TestStatus.FAIL)
        skipped = sum(1 for r in self.results if r.status == TestStatus.NOT_TESTABLE)
        errors = sum(1 for r in self.results if r.status == TestStatus.ERROR)
        testable = total - skipped
        rate = (passed / testable * 100) if testable else 0

        self.card_total.set_value(str(total))
        self.card_passed.set_value(str(passed))
        self.card_failed.set_value(str(failed))
        self.card_skipped.set_value(str(skipped))
        self.card_errors.set_value(str(errors))
        self.card_rate.set_value(f"{rate:.0f}%")

    def _on_finished(self, results: List[TestResult]):
        self.is_running = False
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.clear_btn.setEnabled(True)

        if results:
            self.export_html_btn.setEnabled(True)
            self.export_csv_btn.setEnabled(True)

        duration = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
        self.progress_detail.setText(f"Done in {duration:.1f}s")

        passed = sum(1 for r in self.results if r.status == TestStatus.PASS)
        failed = sum(1 for r in self.results if r.status == TestStatus.FAIL)

        if failed == 0:
            self._set_status("Passed", "#22c55e")
            self._log(f"Completed: {passed} passed")
        else:
            self._set_status("Issues Found", "#ef4444")
            self._log(f"Completed: {failed} failed, {passed} passed")

    def _export_html(self):
        from .reports import generate_html_report
        out = Path(self.output_input.text()) / "zap_verification_report.html"
        generate_html_report(self.results, self.alerts, self.url_input.text(), self.report_input.text(), str(out))
        self._log(f"HTML exported: {out.name}")
        QMessageBox.information(self, "Export", f"Report saved to:\n{out}")

    def _export_csv(self):
        from .reports import generate_csv_report
        out = Path(self.output_input.text()) / "zap_verification_results.csv"
        generate_csv_report(self.results, str(out))
        self._log(f"CSV exported: {out.name}")
        QMessageBox.information(self, "Export", f"Report saved to:\n{out}")


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setFont(QFont("Segoe UI", 10))

    # Set application icon
    app_icon = create_app_icon()
    app.setWindowIcon(app_icon)

    window = ZapGuardWindow()
    window.setWindowIcon(app_icon)
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()

import sys
import datetime
import copy
from PyQt5.QtWidgets import (
	QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
	QTextEdit, QLabel, QTableWidget, QTableWidgetItem,
	QHeaderView, QStatusBar, QFrame
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal

from regex import run_scan, findings
from report import generate_report


# =========================
# THREAD WORKER
# =========================
class ScanWorker(QThread):
	finished = pyqtSignal()

	def __init__(self, option):
		super().__init__()
		self.option = option

	def run(self):
		run_scan(self.option)
		self.finished.emit()


# =========================
# MAIN WINDOW
# =========================
class MainWindow(QMainWindow):
	def __init__(self):
		super().__init__()

		self.setWindowTitle("CredHound | Credential Forensics Suite")
		self.resize(1400, 900)

		self.setup_ui()
		self.update_stats()

	# =========================
	# UI SETUP
	# =========================
	def setup_ui(self):

		central = QWidget()
		self.setCentralWidget(central)

		main_layout = QHBoxLayout(central)

		# =========================
		# LEFT SIDEBAR
		# =========================
		self.sidebar = QFrame()
		self.sidebar.setFixedWidth(220)
		self.sidebar.setStyleSheet("""
			QFrame {
				background-color: #2b2b2b;
			}
			QPushButton {
				background-color: #3a3a3a;
				color: white;
				padding: 10px;
				border-radius: 6px;
				margin: 4px;
				text-align: left;
			}
			QPushButton:hover {
				background-color: #505050;
			}
		""")

		side_layout = QVBoxLayout(self.sidebar)

		title = QLabel("CredHound")
		title.setStyleSheet("font-size:18px; font-weight:bold; color:white;")
		title.setAlignment(Qt.AlignCenter)

		side_layout.addWidget(title)

		self.btn_temp = QPushButton("Temp Files")
		self.btn_config = QPushButton("Config Files")
		self.btn_history = QPushButton("History Files")
		self.btn_browser = QPushButton("Browser Artifacts")

		side_layout.addWidget(self.btn_temp)
		side_layout.addWidget(self.btn_config)
		side_layout.addWidget(self.btn_history)
		side_layout.addWidget(self.btn_browser)

		side_layout.addStretch()

		# =========================
		# RIGHT PANEL
		# =========================
		right_panel = QVBoxLayout()

		# =========================
		# TOP BAR
		# =========================
		top_bar = QFrame()
		top_bar.setStyleSheet("""
			QFrame {
				background-color: #1f1f1f;
				border: 1px solid #444;
			}
		""")

		top_layout = QHBoxLayout(top_bar)

		self.tool_label = QLabel("Credential Exposure Forensics Dashboard")
		self.tool_label.setStyleSheet("font-size:15px; font-weight:bold; color:white;")

		self.stat_label = QLabel("Total Findings: 0")
		self.stat_label.setStyleSheet("font-size:14px; color:#00d4ff;")

		self.btn_report = QPushButton("Generate Report")
		self.btn_clear = QPushButton("Clear")

		top_layout.addWidget(self.tool_label)
		top_layout.addStretch()
		top_layout.addWidget(self.stat_label)
		top_layout.addWidget(self.btn_report)
		top_layout.addWidget(self.btn_clear)

		# =========================
		# TABLE
		# =========================
		self.table = QTableWidget()
		self.table.setColumnCount(3)
		self.table.setHorizontalHeaderLabels(["Source", "Value", "Category"])
		self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

		# =========================
		# LOG BOX
		# =========================
		self.log_box = QTextEdit()
		self.log_box.setReadOnly(True)

		# =========================
		# LEDGER BOX (RAW DATA)
		# =========================
		ledger_title = QLabel("Credential Ledger (Raw Extracted Data)")
		ledger_title.setStyleSheet("font-weight:bold; color:#00ff9c;")

		self.ledger_box = QTextEdit()
		self.ledger_box.setReadOnly(True)
		self.ledger_box.setStyleSheet("""
			background-color: #0b0f14;
			color: #00ff9c;
			font-family: Consolas;
			font-size: 12px;
		""")

		# =========================
		# ADD RIGHT PANEL WIDGETS
		# =========================
		right_panel.addWidget(top_bar)
		right_panel.addWidget(self.table, 5)
		right_panel.addWidget(self.log_box, 2)
		right_panel.addWidget(ledger_title)
		right_panel.addWidget(self.ledger_box, 2)

		main_layout.addWidget(self.sidebar)
		main_layout.addLayout(right_panel)

		# =========================
		# BUTTON ACTIONS
		# =========================
		self.btn_temp.clicked.connect(lambda: self.start_scan(1))
		self.btn_config.clicked.connect(lambda: self.start_scan(2))
		self.btn_history.clicked.connect(lambda: self.start_scan(3))
		self.btn_browser.clicked.connect(self.scan_browser)

		self.btn_report.clicked.connect(self.generate_pdf)
		self.btn_clear.clicked.connect(self.clear_results)

		# =========================
		# STATUS BAR
		# =========================
		self.status = QStatusBar()
		self.setStatusBar(self.status)
		self.status.showMessage("Ready")

	# =========================
	# STATS
	# =========================
	def update_stats(self):
		total = sum(len(v) for v in findings.values())
		self.stat_label.setText(f"Total Findings: {total}")

	# =========================
	# LEDGER
	# =========================
	def add_to_ledger(self, source, value, category):
		t = datetime.datetime.now().strftime("%H:%M:%S")
		self.ledger_box.append(f"[{t}] [{category}] {source} → {value}")

	# =========================
	# SCAN
	# =========================
	def start_scan(self, option):
		self.log(f"Starting scan {option}...")
		self.worker = ScanWorker(option)
		self.worker.finished.connect(self.scan_done)
		self.worker.start()

	def scan_done(self):
		self.populate_table()
		self.update_stats()
		self.status.showMessage("Scan completed")

	# =========================
	# BROWSER SCAN
	# =========================
	def scan_browser(self):
		self.log("Starting browser scan...")
		self.worker = ScanWorker(4)
		self.worker.finished.connect(self.scan_done)
		self.worker.start()

	# =========================
	# POPULATE TABLE
	# =========================
	def populate_table(self):
		self.table.setRowCount(0)

		labels = {1: "TEMP", 2: "CONFIG", 3: "HISTORY", 4: "BROWSER"}

		for cat, rows in findings.items():
			for src, val in rows:
				row = self.table.rowCount()
				self.table.insertRow(row)

				self.table.setItem(row, 0, QTableWidgetItem(str(src)))
				self.table.setItem(row, 1, QTableWidgetItem(str(val)))
				self.table.setItem(row, 2, QTableWidgetItem(labels.get(cat, "-")))

				self.add_to_ledger(src, val, labels.get(cat, "-"))

	# =========================
	# REPORT (FIXED)
	# =========================
	def generate_pdf(self):
		try:
			self.log("Generating fresh report...")

			# CRITICAL FIX: snapshot prevents stale data
			snapshot = copy.deepcopy(findings)

			generate_report(snapshot)

			self.log("Report generated → report.pdf")

		except Exception as e:
			self.log(f"Report error: {e}")

	# =========================
	# CLEAR
	# =========================
	def clear_results(self):
		self.table.setRowCount(0)
		self.log_box.clear()
		self.ledger_box.clear()

		for k in findings:
			findings[k].clear()

		self.update_stats()
		self.status.showMessage("Cleared")

	# =========================
	# LOGGING
	# =========================
	def log(self, msg):
		t = datetime.datetime.now().strftime("%H:%M:%S")
		self.log_box.append(f"[{t}] {msg}")

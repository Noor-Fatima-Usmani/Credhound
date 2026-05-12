import sys
from PyQt5.QtWidgets import QApplication
from gui import MainWindow


if __name__ == "__main__":
    app = QApplication(sys.argv)

    # Load external stylesheet safely
    try:
        with open("style.css", "r", encoding="utf-8") as f:
            app.setStyleSheet(f.read())
    except FileNotFoundError:
        pass

    window = MainWindow()
    window.show()

    sys.exit(app.exec_())
"""
Runs a tool's (possibly slow) work in a background QThread so the GUI
never freezes during scans/analysis. Used by any plugin whose run()
takes more than a blink of an eye.

Usage inside a plugin widget:

    from core.task_manager import Worker

    self.worker = Worker(some_blocking_function, arg1, arg2)
    self.worker.finished.connect(self.on_result)
    self.worker.error.connect(self.on_error)
    self.worker.start()
"""
import traceback
from PyQt6.QtCore import QThread, pyqtSignal


class Worker(QThread):
    finished = pyqtSignal(object)   # emits the function's return value
    error = pyqtSignal(str)         # emits a formatted error string
    progress = pyqtSignal(str)      # optional status text updates

    def __init__(self, func, *args, **kwargs):
        super().__init__()
        self.func = func
        self.args = args
        self.kwargs = kwargs

    def run(self):
        try:
            result = self.func(*self.args, **self.kwargs)
            self.finished.emit(result)
        except Exception:
            self.error.emit(traceback.format_exc())

"""
Centralized logging for every plugin/tool in Rupux.
All tools should use: from core.logger import get_logger
"""
import logging
import os
from datetime import datetime
from core.config import LOG_DIR

_LOG_FILE = os.path.join(LOG_DIR, f"rupux_{datetime.now().strftime('%Y%m%d')}.log")

_formatter = logging.Formatter(
    "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%H:%M:%S",
)

_file_handler = logging.FileHandler(_LOG_FILE, encoding="utf-8")
_file_handler.setFormatter(_formatter)

_console_handler = logging.StreamHandler()
_console_handler.setFormatter(_formatter)


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.DEBUG)
        logger.addHandler(_file_handler)
        logger.addHandler(_console_handler)
        logger.propagate = False
    return logger

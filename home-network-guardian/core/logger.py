"""
Logging setup for the Home Network Guardian.

Call setup_logging() once at application startup to configure a named
"guardian" logger that writes to both a rotating file and the console.
All modules obtain their logger via logging.getLogger("guardian").
"""

import logging
import logging.handlers
from pathlib import Path


_FILE_FORMAT    = "%(asctime)s [%(levelname)-8s] %(message)s"
_CONSOLE_FORMAT = "[%(levelname)s] %(message)s"
_DATE_FORMAT    = "%Y-%m-%d %H:%M:%S"

# Maximum log file size before rotation (1 MB)
_MAX_BYTES    = 1_000_000
# Number of rotated backup files to keep
_BACKUP_COUNT = 3


def setup_logging(data_dir: Path, level: str = "INFO") -> logging.Logger:
    """Configure the application-wide "guardian" logger.

    Creates a rotating file handler at ``data_dir/guardian.log`` and a
    console (stderr) handler.  Safe to call multiple times — existing
    handlers are cleared before new ones are added.

    Args:
        data_dir: Directory where ``guardian.log`` will be written.
                  Created automatically if it does not exist.
        level:    Log level string ("DEBUG", "INFO", "WARNING", "ERROR").
                  Defaults to "INFO".

    Returns:
        The configured ``logging.Logger`` instance.
    """
    data_dir.mkdir(parents=True, exist_ok=True)
    log_file = data_dir / "guardian.log"

    log_level = getattr(logging, level.upper(), logging.INFO)

    logger = logging.getLogger("guardian")
    logger.setLevel(log_level)

    # Clear any existing handlers (safe for repeated calls / hot-reload)
    logger.handlers.clear()
    logger.propagate = False

    # Rotating file handler
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=_MAX_BYTES,
        backupCount=_BACKUP_COUNT,
        encoding="utf-8",
    )
    file_handler.setLevel(log_level)
    file_handler.setFormatter(
        logging.Formatter(_FILE_FORMAT, datefmt=_DATE_FORMAT))
    logger.addHandler(file_handler)

    # Console handler (INFO and above, regardless of chosen level)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter(_CONSOLE_FORMAT))
    logger.addHandler(console_handler)

    logger.info("Logging initialised — file: %s  level: %s", log_file, level)
    return logger


def get_logger() -> logging.Logger:
    """Return the application logger (must call setup_logging first).

    Returns:
        The "guardian" logger instance.
    """
    return logging.getLogger("guardian")

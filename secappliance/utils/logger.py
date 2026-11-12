import logging
import sys
from pathlib import Path
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Define colors for log levels
COLORS = {
    'DEBUG': Fore.CYAN,
    'INFO': Fore.GREEN,
    'WARNING': Fore.YELLOW,
    'ERROR': Fore.RED,
    'CRITICAL': Fore.RED + Style.BRIGHT,
}

class ColoredFormatter(logging.Formatter):
    """Custom formatter to add colors to log levels."""
    def format(self, record):
        log_message = super().format(record)
        return COLORS.get(record.levelname, '') + log_message + Style.RESET_ALL

LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'


def setup_logger(name: str = 'secappliance', level: int = logging.INFO) -> logging.Logger:
    """
    Set up a logger with colorized console output only.

    File logging is opt-in through attach_file_handler(), so importing this
    module never touches the file system (a read-only working directory must not
    break startup).

    Args:
        name: Logger name.
        level: Logging level.

    Returns:
        Configured logger instance.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Prevent adding multiple handlers if already configured
    if logger.handlers:
        return logger

    # Console handler with color
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(ColoredFormatter(fmt=LOG_FORMAT, datefmt=LOG_DATE_FORMAT))
    logger.addHandler(console_handler)

    return logger


def attach_file_handler(logger: logging.Logger, log_path: Path | str, level: int | None = None) -> bool:
    """
    Attach a plain file handler to an already configured logger.

    Any previous file handler is replaced, so this is safe to call repeatedly.
    A path that cannot be opened (read-only, permission denied) leaves the logger
    on console output and warns instead of raising.

    Args:
        logger: Logger to attach to.
        log_path: File to write to.
        level: Handler level; defaults to the logger's level.

    Returns:
        True if the handler was attached, False if file logging is unavailable.
    """
    for handler in list(logger.handlers):
        if isinstance(handler, logging.FileHandler):
            logger.removeHandler(handler)
            handler.close()

    path = Path(log_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(path, encoding='utf-8')
    except OSError as exc:
        logger.warning(f"File logging disabled, writing to console only ({path}): {exc}")
        return False

    file_handler.setLevel(logger.level if level is None else level)
    file_handler.setFormatter(logging.Formatter(fmt=LOG_FORMAT, datefmt=LOG_DATE_FORMAT))
    logger.addHandler(file_handler)
    return True


# Default logger instance
logger = setup_logger()
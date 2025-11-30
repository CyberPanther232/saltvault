import logging
import os
from logging.handlers import RotatingFileHandler

def get_logger(name: str) -> logging.Logger:
    """Create and configure a logger (idempotent)."""
    # Correct assignment (was == causing NameError)
    log_dir = os.environ.get('LOG_DIRECTORY', 'logs')

    # Ensure directory exists
    os.makedirs(log_dir, exist_ok=True)

    if name == 'werkzeug':
        logfile = os.path.join(log_dir, 'http.log')
        handler = RotatingFileHandler(logfile, maxBytes=5 * 1024 * 1024, backupCount=5)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        werkzeug_logger = logging.getLogger('werkzeug')
        if not any(isinstance(h, RotatingFileHandler) and getattr(h, 'baseFilename', '') == logfile for h in werkzeug_logger.handlers):
            werkzeug_logger.setLevel(logging.INFO)
            werkzeug_logger.addHandler(handler)
        return werkzeug_logger

    logger = logging.getLogger(name)
    app_log_path = os.path.join(log_dir, 'app.log')
    if not any(isinstance(h, RotatingFileHandler) and getattr(h, 'baseFilename', '') == app_log_path for h in logger.handlers):
        logger.setLevel(logging.INFO)
        handler = RotatingFileHandler(app_log_path, maxBytes=5 * 1024 * 1024, backupCount=5)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger

def log_event(event_type: str, message: str, severity: str = 'INFO') -> None:
    """Log an event with a specific type and severity."""
    logger = get_logger('SaltVaultApp')
    log_func = getattr(logger, severity.lower(), logger.info)
    log_func(f'[{event_type}] {message}')
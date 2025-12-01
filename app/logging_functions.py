import logging
import os
from logging.handlers import RotatingFileHandler

def get_logger(name: str) -> logging.Logger:
    """Create and configure a logger."""
    log_dir = os.environ.get('LOG_DIRECTORY', 'logs')
    os.makedirs(log_dir, exist_ok=True)

    if name == 'werkzeug':
        logfile = os.path.join(log_dir, 'http.log')
        handler = RotatingFileHandler(logfile, maxBytes=5 * 1024 * 1024, backupCount=5)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger = logging.getLogger('werkzeug')
        if not logger.handlers:
            logger.setLevel(logging.INFO)
            logger.addHandler(handler)
        return logger

    # For the application logger
    logger = logging.getLogger('app')
    if not logger.handlers:
        app_log_path = os.path.join(log_dir, 'app.log')
        handler = RotatingFileHandler(app_log_path, maxBytes=5 * 1024 * 1024, backupCount=5)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.setLevel(logging.INFO)
        logger.addHandler(handler)
    return logger

def log_event(event_type: str, message: str, severity: str = 'INFO') -> None:
    """Log an event with a specific type and severity."""
    logger = get_logger('app')
    log_func = getattr(logger, severity.lower(), logger.info)
    log_func(f'[{event_type}] {message}')
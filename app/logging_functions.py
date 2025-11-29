import logging
import os
from logging.handlers import RotatingFileHandler

def get_logger(name):
    """Create and configure a logger."""
    
    log_dir = os.environ.get('LOG_DIRECTORY', 'logs')
    os.makedirs(log_dir, exist_ok=True)
    
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        
        # Create a rotating file handler
        handler = RotatingFileHandler(
            os.path.join(log_dir, 'app.log'),
            maxBytes=1024 * 1024 * 5,  # 5 MB
            backupCount=5
        )
        
        # Create a logging format
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        
        # Add the handler to the logger
        logger.addHandler(handler)
        
    return logger

def log_event(event_type, message, severity='INFO'):
    """Log an event with a specific type and severity."""
    logger = get_logger('SaltVaultApp')
    log_func = getattr(logger, severity.lower(), logger.info)
    log_func(f'[{event_type}] {message}')
from app import create_app
from app.logging_functions import get_logger, log_event
import os

app = create_app()

if __name__ == '__main__':
    logger = get_logger('main')
    logger.info('Starting SaltVault application')
    log_event('APPLICATION_START', 'SaltVault application has started')
    app.run(debug=os.environ.get('DEBUG', True), host=os.environ.get('HOST', 'localhost'), port=int(os.environ.get('PORT', 80)))
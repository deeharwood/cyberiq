import os

# Bind to the port provided by Railway
port = os.environ.get('PORT', '8080')
bind = f"0.0.0.0:{port}"

# Worker configuration
workers = 2
worker_class = 'sync'
timeout = 120

# Logging
accesslog = '-'
errorlog = '-'
loglevel = 'info'

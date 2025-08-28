"""
Logging utility for CyberGuard Server.
Handles logging configuration and log message formatting.
"""

import logging
import os

def setup_logger(name: str = "CyberGuard"):
    """Set up logging configuration."""
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    log_file = os.getenv("LOG_FILE", None)

    logger = logging.getLogger(name)
    logger.setLevel(log_level)

    # Create console handler
    ch = logging.StreamHandler()
    ch.setLevel(log_level)

    # Create file handler if log_file is specified
    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setLevel(log_level)
        logger.addHandler(fh)

    # Create formatter and add it to handlers
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    if log_file:
        fh.setFormatter(formatter)

    # Add handlers to the logger
    logger.addHandler(ch)
    if log_file:
        logger.addHandler(fh)

    return logger

# Set up the logger
logger = setup_logger()

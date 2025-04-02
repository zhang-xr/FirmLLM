import logging
import os
from typing import Optional, Dict
from pathlib import Path

class LogManager:
    """Centralized logging management for the firmware analyzer"""
    
    _instances: Dict[str, logging.Logger] = {}
    _initialized: bool = False
    
    @classmethod
    def setup(cls, base_log_path: str, console_level: int = logging.INFO, file_level: int = logging.DEBUG):
        """Initialize logging configuration"""
        if cls._initialized:
            return
            
        # Create log directory if it doesn't exist
        os.makedirs(base_log_path, exist_ok=True)
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)
        
        # Clear any existing handlers
        root_logger.handlers.clear()
        
        # Create formatters
        console_formatter = logging.Formatter('%(levelname)s %(name)s: %(message)s')
        file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(console_level)
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)
        
        # File handler for main log
        main_log_path = os.path.join(base_log_path, 'analyzer.log')
        file_handler = logging.FileHandler(main_log_path)
        file_handler.setLevel(file_level)
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)
        
        cls._initialized = True
    
    @classmethod
    def get_logger(cls, name: str, log_file: Optional[str] = None) -> logging.Logger:
        """Get a logger with optional separate log file
        
        Args:
            name: Logger name (usually module name)
            log_file: Optional separate log file path for this logger
            
        Returns:
            logging.Logger: Configured logger instance
        """
        if name in cls._instances:
            return cls._instances[name]
            
        logger = logging.getLogger(name)
        
        # Add separate file handler if specified
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(
                logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            )
            file_handler.setLevel(logging.DEBUG)
            logger.addHandler(file_handler)
        
        cls._instances[name] = logger
        return logger

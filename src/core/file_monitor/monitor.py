import logging
import os
import time
from pathlib import Path
from typing import Set
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from src.ml.classifiers.data_classifier import DataClassifier
from src.policy.engine import PolicyEngine

logger = logging.getLogger(__name__)

class FileEventHandler(FileSystemEventHandler):
    def __init__(self, policy_engine: PolicyEngine, classifier: DataClassifier):
        self.policy_engine = policy_engine
        self.classifier = classifier
        self.monitored_extensions: Set[str] = {'.txt', '.doc', '.docx', '.pdf', '.xls', '.xlsx'}

    def on_modified(self, event):
        if event.is_directory:
            return
        
        file_path = Path(event.src_path)
        if file_path.suffix.lower() not in self.monitored_extensions:
            return

        try:
            # Check if file contains sensitive data
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                if self.classifier.is_sensitive(content):
                    logger.warning(f"Sensitive data detected in file: {file_path}")
                    self.policy_engine.handle_sensitive_file_access(str(file_path))
        except Exception as e:
            logger.error(f"Error processing file {file_path}: {e}")

    def on_created(self, event):
        if event.is_directory:
            return
        logger.info(f"New file created: {event.src_path}")
        self.on_modified(event)

    def on_moved(self, event):
        if event.is_directory:
            return
        logger.info(f"File moved/renamed: {event.src_path} -> {event.dest_path}")
        # Check both source and destination files
        self.on_modified(event)

class FileMonitor:
    def __init__(self, policy_engine: PolicyEngine):
        self.policy_engine = policy_engine
        self.classifier = DataClassifier()
        self.observer = Observer()
        self.watched_paths = set()

    def add_watch_path(self, path: str):
        """Add a new path to monitor"""
        if not os.path.exists(path):
            logger.error(f"Path does not exist: {path}")
            return False

        if path in self.watched_paths:
            logger.warning(f"Path already being monitored: {path}")
            return True

        try:
            event_handler = FileEventHandler(self.policy_engine, self.classifier)
            self.observer.schedule(event_handler, path, recursive=True)
            self.watched_paths.add(path)
            logger.info(f"Started monitoring path: {path}")
            return True
        except Exception as e:
            logger.error(f"Error adding watch path {path}: {e}")
            return False

    def remove_watch_path(self, path: str):
        """Remove a path from monitoring"""
        if path not in self.watched_paths:
            logger.warning(f"Path not being monitored: {path}")
            return

        try:
            # Find and remove the observer for this path
            for watch in self.observer._watches.copy():
                if watch.path == path:
                    self.observer.unschedule(watch)
                    self.watched_paths.remove(path)
                    logger.info(f"Stopped monitoring path: {path}")
                    break
        except Exception as e:
            logger.error(f"Error removing watch path {path}: {e}")

    def start(self):
        """Start the file monitoring service"""
        if not self.observer.is_alive():
            self.observer.start()
            logger.info("File monitoring service started")

    def stop(self):
        """Stop the file monitoring service"""
        if self.observer.is_alive():
            self.observer.stop()
            self.observer.join()
            logger.info("File monitoring service stopped")
            self.watched_paths.clear()
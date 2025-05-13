# Combine content from src/core/file_monitor/monitor.py and watcher.py
import logging
import os
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent
from threading import Event
from typing import Set, Dict, Optional

from src.ml.classifiers.data_classifier import DataClassifier
from src.policy.engine import PolicyEngine
from src.utils.encryption import encrypt_file

logger = logging.getLogger(__name__)

class FileEventHandler(FileSystemEventHandler):
    def __init__(self, monitor: 'FileMonitor'):
        self.monitor = monitor
        self.policy_engine = monitor.policy_engine
        self.classifier = monitor.classifier
        self.monitored_extensions: Set[str] = {'.txt', '.doc', '.docx', '.pdf', '.xls', '.xlsx'}

    def on_modified(self, event: FileSystemEvent):
        if event.is_directory:
            return
        
        file_path = Path(event.src_path)
        if file_path.suffix.lower() not in self.monitored_extensions:
            return

        self.monitor.handle_file_event('modified', str(file_path))

    def on_created(self, event: FileSystemEvent):
        if event.is_directory:
            return
        logger.info(f"New file created: {event.src_path}")
        self.on_modified(event)

    def on_moved(self, event: FileSystemEvent):
        if event.is_directory:
            return
        logger.info(f"File moved/renamed: {event.src_path} -> {event.dest_path}")
        self.monitor.handle_file_event('moved', event.dest_path, event.src_path)

class FileMonitor:
    def __init__(self, policy_engine: PolicyEngine):
        self.policy_engine = policy_engine
        self.classifier = DataClassifier()
        self.observer = Observer()
        self.watched_paths: Set[str] = set()
        self.stop_event = Event()
        self.encryption_enabled = True
        self.sensitive_files: Dict[str, float] = {}

    def add_watch_path(self, path: str) -> bool:
        """Add a new path to monitor"""
        if not os.path.exists(path):
            logger.error(f"Path does not exist: {path}")
            return False

        if path in self.watched_paths:
            logger.warning(f"Path already being monitored: {path}")
            return True

        try:
            event_handler = FileEventHandler(self)
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

    def handle_file_event(self, event_type: str, file_path: str, src_path: Optional[str] = None):
        """Handle file system events"""
        try:
            if not Path(file_path).exists() or not os.path.isfile(file_path):
                return

            # Skip if file is already being processed
            if file_path in self.sensitive_files:
                return

            # Check file content for sensitivity
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                sensitivity_score = self.classifier.analyze_sensitivity(content)

            if sensitivity_score > self.policy_engine.get_sensitivity_threshold():
                self.sensitive_files[file_path] = sensitivity_score
                logger.warning(f"Sensitive content detected in file: {file_path} (score: {sensitivity_score})")

                if self.encryption_enabled:
                    encrypt_file(file_path)
                    logger.info(f"Encrypted sensitive file: {file_path}")

                # Log the violation
                self.policy_engine.log_file_violation(
                    file_path=file_path,
                    event_type=event_type,
                    sensitivity_score=sensitivity_score,
                    src_path=src_path
                )

        except Exception as e:
            logger.error(f"Error handling file event for {file_path}: {e}")
        finally:
            if file_path in self.sensitive_files:
                del self.sensitive_files[file_path]

    def start(self):
        """Start the file monitoring service"""
        if not self.observer.is_alive():
            # Add default paths to watch
            default_paths = [
                os.path.expanduser('~/Documents'),
                os.path.expanduser('~/Downloads')
            ]
            for path in default_paths:
                self.add_watch_path(path)

            self.observer.start()
            logger.info("File monitoring service started")

    def stop(self):
        """Stop the file monitoring service"""
        if self.observer.is_alive():
            self.observer.stop()
            self.observer.join(timeout=2.0)
            logger.info("File monitoring service stopped")
            self.watched_paths.clear()

    def set_encryption_enabled(self, enabled: bool):
        """Enable or disable encryption of sensitive files"""
        self.encryption_enabled = enabled
        logger.info(f"File encryption {'enabled' if enabled else 'disabled'}")
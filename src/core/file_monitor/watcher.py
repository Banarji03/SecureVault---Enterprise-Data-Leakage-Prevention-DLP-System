import logging
import os
from pathlib import Path
from threading import Thread, Event
from typing import Set, Dict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

from src.ml.classifiers.data_classifier import DataClassifier
from src.policy.engine import PolicyEngine
from src.utils.encryption import encrypt_file

logger = logging.getLogger(__name__)

class FileEventHandler(FileSystemEventHandler):
    def __init__(self, watcher: 'FileSystemWatcher'):
        self.watcher = watcher
        self.classifier = DataClassifier()

    def on_modified(self, event: FileSystemEvent):
        if event.is_directory:
            return
        self.watcher.handle_file_event('modified', event.src_path)

    def on_created(self, event: FileSystemEvent):
        if event.is_directory:
            return
        self.watcher.handle_file_event('created', event.src_path)

    def on_moved(self, event: FileSystemEvent):
        if event.is_directory:
            return
        self.watcher.handle_file_event('moved', event.dest_path, event.src_path)

class FileSystemWatcher:
    def __init__(self, policy_engine: PolicyEngine):
        self.policy_engine = policy_engine
        self.observer = Observer()
        self.event_handler = FileEventHandler(self)
        self.watched_paths: Set[str] = set()
        self.stop_event = Event()
        self.encryption_enabled = True
        self.sensitive_files: Dict[str, float] = {}

    def add_watch_path(self, path: str):
        """Add a new path to watch"""
        try:
            if path not in self.watched_paths:
                self.observer.schedule(self.event_handler, path, recursive=True)
                self.watched_paths.add(path)
                logger.info(f"Added watch path: {path}")
        except Exception as e:
            logger.error(f"Error adding watch path {path}: {e}")

    def remove_watch_path(self, path: str):
        """Remove a watched path"""
        if path in self.watched_paths:
            self.watched_paths.remove(path)
            # Recreate observer with updated paths
            self.restart()
            logger.info(f"Removed watch path: {path}")

    def handle_file_event(self, event_type: str, file_path: str, src_path: str = None):
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
                sensitivity_score = self.event_handler.classifier.analyze_sensitivity(content)

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
        """Start file system monitoring"""
        if not self.observer.is_alive():
            # Add default paths to watch
            default_paths = [
                os.path.expanduser('~/Documents'),
                os.path.expanduser('~/Downloads')
            ]
            for path in default_paths:
                self.add_watch_path(path)

            self.observer.start()
            logger.info("File system monitoring started")

    def stop(self):
        """Stop file system monitoring"""
        if self.observer.is_alive():
            self.observer.stop()
            self.observer.join(timeout=2.0)
            logger.info("File system monitoring stopped")

    def restart(self):
        """Restart file system monitoring"""
        self.stop()
        self.observer = Observer()
        for path in self.watched_paths:
            self.observer.schedule(self.event_handler, path, recursive=True)
        self.start()

    def set_encryption_enabled(self, enabled: bool):
        """Enable or disable encryption of sensitive files"""
        self.encryption_enabled = enabled
        logger.info(f"File encryption {'enabled' if enabled else 'disabled'}")
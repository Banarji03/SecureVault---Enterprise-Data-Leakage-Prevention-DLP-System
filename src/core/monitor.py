from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from utils.logger import Logger

class FileEventHandler(FileSystemEventHandler):
    def __init__(self, detection_engine):
        self.detection_engine = detection_engine
        self.logger = Logger()

    def on_modified(self, event):
        if not event.is_directory:
            self.detection_engine.analyze_file(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self.detection_engine.analyze_file(event.src_path)

class FileMonitor:
    def __init__(self, detection_engine):
        self.detection_engine = detection_engine
        self.observer = Observer()
        self.logger = Logger()

    def start(self, path="."):
        try:
            event_handler = FileEventHandler(self.detection_engine)
            self.observer.schedule(event_handler, path, recursive=True)
            self.observer.start()
            self.logger.info(f"File monitoring started for path: {path}")
        except Exception as e:
            self.logger.error(f"Error starting file monitor: {str(e)}")
            raise

    def stop(self):
        self.observer.stop()
        self.observer.join()
import logging
import sys
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('securevault.log')
    ]
)

logger = logging.getLogger(__name__)

def setup_directories():
    """Create necessary directories if they don't exist"""
    base_dir = Path(__file__).parent
    dirs = [
        base_dir / 'core',
        base_dir / 'ml' / 'classifiers',
        base_dir / 'ml' / 'behavioral',
        base_dir / 'policy',
        base_dir / 'dashboard',
        base_dir / 'utils',
        base_dir / 'config'
    ]
    
    for dir_path in dirs:
        dir_path.mkdir(parents=True, exist_ok=True)
        logger.info(f'Created directory: {dir_path}')

def main():
    try:
        # Setup project structure
        setup_directories()
        logger.info('SecureVault DLP System initialized')
        
        # Initialize components
        from src.policy.engine import PolicyEngine
        from src.core.clipboard.monitor import ClipboardMonitor
        from src.core.file_monitor.watcher import FileSystemWatcher
        from src.dashboard.app import create_app
        
        # Start policy engine
        policy_engine = PolicyEngine()
        
        # Start monitors
        clipboard_monitor = ClipboardMonitor(policy_engine)
        clipboard_monitor.start()
        
        file_watcher = FileSystemWatcher(policy_engine)
        file_watcher.start()
        
        # Start dashboard
        app = create_app(policy_engine)
        app.run(host='0.0.0.0', port=5000)
        
    except Exception as e:
        logger.error(f'Failed to start SecureVault: {e}')
        sys.exit(1)

if __name__ == '__main__':
    main()
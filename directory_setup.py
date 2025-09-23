import os
import logging

logger = logging.getLogger(__name__)

def create_output_directory(output_dir):
    """Create output directory structure"""
    try:
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(os.path.join(output_dir, 'pdf'), exist_ok=True)
        os.makedirs(os.path.join(output_dir, 'csv'), exist_ok=True)
        logger.info(f"Output directory created: {output_dir}")
    except Exception as e:
        logger.error(f"Failed to create output directory: {e}")
        raise

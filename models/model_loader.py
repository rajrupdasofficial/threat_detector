import os
import sys
import logging
import tensorflow as tf
from tensorflow.keras.preprocessing.text import tokenizer_from_json
from tqdm import tqdm

logger = logging.getLogger(__name__)

def load_model_components(model_path, tokenizer_path, label_mapping_path):
    """Load the trained model, tokenizer, and label mappings"""
    print("Loading model components...")

    with tqdm(total=3, desc="Loading Components", unit="component") as pbar:
        try:
            # Load model
            if os.path.exists(model_path):
                model = tf.keras.models.load_model(model_path)
                logger.info(f"Model loaded successfully from {model_path}")
                pbar.set_description("Model loaded")
                pbar.update(1)
            else:
                logger.error(f"Model file not found: {model_path}")
                sys.exit(1)

            # Load tokenizer
            if os.path.exists(tokenizer_path):
                with open(tokenizer_path, 'r') as f:
                    tokenizer_json = f.read()
                    tokenizer = tokenizer_from_json(tokenizer_json)
                logger.info("Tokenizer loaded successfully")
                pbar.set_description("Tokenizer loaded")
                pbar.update(1)
            else:
                logger.error(f"Tokenizer file not found: {tokenizer_path}")
                sys.exit(1)

            # Load label mappings
            if os.path.exists(label_mapping_path):
                label_to_int = {}
                int_to_label = {}
                with open(label_mapping_path, 'r') as f:
                    for line in f:
                        label, idx = line.strip().split(':')
                        label_to_int[label] = int(idx)
                        int_to_label[int(idx)] = label
                logger.info(f"Loaded {len(label_to_int)} label mappings")
                pbar.set_description("Labels loaded")
                pbar.update(1)
            else:
                logger.error(f"Label mapping file not found: {label_mapping_path}")
                sys.exit(1)

            return model, tokenizer, label_to_int, int_to_label

        except Exception as e:
            logger.error(f"Error loading model components: {e}")
            sys.exit(1)

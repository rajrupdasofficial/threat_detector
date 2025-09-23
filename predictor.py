import numpy as np
import logging
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tqdm import tqdm

logger = logging.getLogger(__name__)

def predict_vulnerability(url, model, tokenizer, int_to_label, text, max_len=300):
    """
    Predict vulnerability for a given URL with progress tracking
    """
    logger.info(f"Analyzing URL: {url}")

    # Progress tracking
    with tqdm(total=3, desc="Vulnerability Prediction", unit="step") as pbar:

        pbar.set_description("Tokenizing text")
        # Preprocess text using the same tokenizer
        sequences = tokenizer.texts_to_sequences([text])
        X = pad_sequences(sequences, maxlen=max_len, padding='post', truncating='post')
        pbar.update(1)

        pbar.set_description("Running ML prediction")
        # Make prediction
        predictions = model.predict(X, verbose=0)
        predicted_class_idx = np.argmax(predictions[0])
        confidence = float(predictions[0][predicted_class_idx])
        pbar.update(1)

        pbar.set_description("Processing results")
        # Get predicted label
        predicted_label = int_to_label.get(predicted_class_idx, "Unknown")

        # Get top 3 predictions
        top_3_indices = np.argsort(predictions[0])[-3:][::-1]
        top_3_predictions = []
        for idx in top_3_indices:
            label = int_to_label.get(idx, f"Class_{idx}")
            conf = float(predictions[0][idx])
            top_3_predictions.append((label, conf))
        pbar.update(1)

    return {
        'url': url,
        'predicted_vulnerability': predicted_label,
        'confidence': confidence,
        'top_3_predictions': top_3_predictions,
        'extracted_features': {}  # Features are passed separately in main
    }

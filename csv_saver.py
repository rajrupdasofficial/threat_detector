import os
import pandas as pd
from datetime import datetime
from urllib.parse import urlparse
from tqdm import tqdm
import logging

logger = logging.getLogger(__name__)

def save_csv_report(result, output_dir):
    """Save result to CSV format"""
    print("\nSaving CSV report...")

    with tqdm(total=3, desc="Generating CSV", unit="file") as pbar:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        domain = urlparse(result['url']).netloc.replace('.', '_').replace(':', '_')
        csv_filename = os.path.join(output_dir, 'csv', f'{domain}_{timestamp}.csv')

        pbar.set_description("Creating main CSV")
        # Prepare data for CSV
        csv_data = {
            'URL': [result['url']],
            'Analysis_Timestamp': [result['analysis_timestamp']],
            'Risk_Level': [result['risk_level']],
            'Predicted_Vulnerability': [result['predicted_vulnerability']],
            'Confidence': [f"{result['confidence']:.4f}"],
            'Top_Prediction_1': [f"{result['top_3_predictions'][0][0]} ({result['top_3_predictions'][0][1]:.3f})"],
            'Top_Prediction_2': [f"{result['top_3_predictions'][1][0]} ({result['top_3_predictions'][1][1]:.3f})"],
            'Top_Prediction_3': [f"{result['top_3_predictions'][2][0]} ({result['top_3_predictions'][2][1]:.3f})"],
            'Security_Headers_Present': [bool(result['extracted_features'].get('security_headers', ''))],
            'Technologies_Detected': [result['extracted_features'].get('technologies', 'None')],
            'Forms_Found': [bool(result['extracted_features'].get('forms', ''))],
            'Recommendations_Count': [len(result['recommendations'])]
        }

        df = pd.DataFrame(csv_data)
        df.to_csv(csv_filename, index=False)
        pbar.update(1)

        pbar.set_description("Creating recommendations CSV")
        # Also save detailed recommendations
        rec_filename = os.path.join(output_dir, 'csv', f'{domain}_{timestamp}_recommendations.csv')
        rec_data = {'Recommendation': result['recommendations']}
        rec_df = pd.DataFrame(rec_data)
        rec_df.to_csv(rec_filename, index=False)
        pbar.update(1)

        pbar.set_description("Creating features CSV")
        # Save detailed features
        features_filename = os.path.join(output_dir, 'csv', f'{domain}_{timestamp}_features.csv')
        features_data = []
        for key, value in result['extracted_features'].items():
            features_data.append({'Feature_Type': key, 'Content': value[:500] if value else 'None'})

        features_df = pd.DataFrame(features_data)
        features_df.to_csv(features_filename, index=False)
        pbar.update(1)

    logger.info(f"CSV reports saved:")
    logger.info(f"  Main report: {csv_filename}")
    logger.info(f"  Recommendations: {rec_filename}")
    logger.info(f"  Features: {features_filename}")

    return [csv_filename, rec_filename, features_filename]

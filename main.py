import os
import sys
import argparse
import logging
from datetime import datetime
import warnings
from tqdm import tqdm

from directory_setup import create_output_directory
from session_setup import setup_session
from models.model_loader import load_model_components
from feature_extractor import extract_website_features, features_to_text
from xss_checker import check_xss
from ssl_checker import check_ssl
from script_issues_checker import check_script_issues
from predictor import predict_vulnerability
from risk_assessor import assess_risk_level
from recommendation_generator import generate_recommendations
from csv_saver import save_csv_report
from pdf_saver import save_pdf_report, PDF_AVAILABLE

warnings.filterwarnings('ignore')
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    parser = argparse.ArgumentParser(description='Website Vulnerability Predictor with Progress Tracking and Report Generation')
    parser.add_argument('url', help='URL to analyze for vulnerabilities')
    parser.add_argument('--model', default='deep_model.keras', help='Path to trained model')
    parser.add_argument('--tokenizer', default='tokenizer.json', help='Path to tokenizer file')
    parser.add_argument('--labels', default='label_to_int.txt', help='Path to label mapping file')
    parser.add_argument('--output-dir', default='ml_analyze_out', help='Output directory for reports')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--no-pdf', action='store_true', help='Skip PDF generation')
    parser.add_argument('--no-csv', action='store_true', help='Skip CSV generation')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'https://' + args.url

    try:
        print(f"🔍 Starting vulnerability analysis for: {args.url}")
        print(f"📁 Reports will be saved to: {args.output_dir}")

        # Setup
        create_output_directory(args.output_dir)
        session = setup_session()

        # Load model components
        model, tokenizer, label_to_int, int_to_label = load_model_components(
            args.model, args.tokenizer, args.labels
        )

        # Perform specific checks
        with tqdm(total=3, desc="Performing Specific Checks", unit="check") as pbar:
            pbar.set_description("Checking XSS")
            xss_results = check_xss(args.url, session)
            pbar.update(1)

            pbar.set_description("Checking SSL")
            ssl_results = check_ssl(args.url)
            pbar.update(1)

            pbar.set_description("Checking Script Issues")
            script_results = check_script_issues(args.url, session)
            pbar.update(1)

        # Extract features (integrate specific checks)
        features = extract_website_features(args.url, session)
        features['xss_check'] = xss_results
        features['ssl_check'] = ssl_results
        features['script_check'] = script_results

        text = features_to_text(features)

        # Predict
        result = predict_vulnerability(
            args.url, model, tokenizer, int_to_label, text
        )

        # Assess risk and recommendations
        result['risk_level'] = assess_risk_level(result['confidence'], result['predicted_vulnerability'])
        result['recommendations'] = generate_recommendations(features, result['predicted_vulnerability'])
        result['analysis_timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Display results (same as original)
        print("\n" + "="*60)
        print("WEBSITE VULNERABILITY ANALYSIS REPORT")
        print("="*60)
        print(f"URL: {result['url']}")
        print(f"Analysis Time: {result['analysis_timestamp']}")
        print(f"Risk Level: {result['risk_level']}")
        print(f"Predicted Vulnerability: {result['predicted_vulnerability']}")
        print(f"Confidence: {result['confidence']:.2%}")

        print("\nTop 3 Predictions:")
        for i, (label, conf) in enumerate(result['top_3_predictions'], 1):
            print(f"  {i}. {label} ({conf:.2%})")

        print("\nSecurity Recommendations:")
        for i, rec in enumerate(result['recommendations'], 1):
            print(f"  {i}. {rec}")

        if args.verbose:
            print("\nExtracted Features:")
            for key, value in result['extracted_features'].items():
                if value:
                    print(f"  {key}: {value[:100]}...")

        print("\n" + "="*60)

        # Save reports
        saved_files = []

        if not args.no_csv:
            try:
                csv_files = save_csv_report(result, args.output_dir)
                saved_files.extend(csv_files)
                print("✅ CSV reports generated successfully")
            except Exception as e:
                logger.error(f"Failed to save CSV report: {e}")

        if not args.no_pdf:
            try:
                if PDF_AVAILABLE:
                    pdf_file = save_pdf_report(result, args.output_dir)
                    saved_files.append(pdf_file)
                    print("✅ PDF report generated successfully")
                else:
                    print("⚠️  PDF generation skipped (reportlab not available)")
            except Exception as e:
                logger.error(f"Failed to save PDF report: {e}")

        if saved_files:
            print(f"\n📋 Analysis Complete! Reports saved:")
            for file in saved_files:
                print(f"   📄 {os.path.basename(file)}")
            print(f"\n📁 All reports saved in: {args.output_dir}")
        else:
            print("\n⚠️  No reports were generated")

    except KeyboardInterrupt:
        print("\n❌ Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

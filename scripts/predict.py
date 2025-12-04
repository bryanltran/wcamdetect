import sys
import pickle
import numpy as np
import pandas as pd
from pathlib import Path
from parse_pcap import PCAPFeatureExtractor

def predict_flow(pcap_file):
    """Predict whether a PCAP is camera or non-camera"""
    
    # Load models
    project_root = Path(__file__).parent.parent
    models_dir = project_root / "data" / "models"
    
    models = {}
    model_files = {
        'Random Forest': 'random_forest_model.pkl',
        'SVM': 'svm_model.pkl',
        'KNN': 'knn_model.pkl'
    }
    
    for name, filename in model_files.items():
        model_path = models_dir / filename
        if model_path.exists():
            with open(model_path, 'rb') as f:
                models[name] = pickle.load(f)
    
    if not models:
        return None, "No models found! Run train_model.py first."
    
    # Extract features
    extractor = PCAPFeatureExtractor()
    features = extractor.extract_features(pcap_file)
    
    if features is None:
        return None, "Could not extract features from PCAP"
    
    # Prepare for prediction
    feature_df = pd.DataFrame([features])
    feature_df = feature_df.fillna(0)
    
    # Predict with all models
    predictions = {}
    
    for name, model_data in models.items():
        model = model_data['model']
        scaler = model_data['scaler']
        feature_names = model_data['feature_names']
        
        # Ensure all features present
        for col in feature_names:
            if col not in feature_df.columns:
                feature_df[col] = 0
        
        X = feature_df[feature_names]
        
        # Scale if needed
        if scaler is not None:
            X = scaler.transform(X)
        
        # Predict
        prediction = model.predict(X)[0]
        probabilities = model.predict_proba(X)[0]
        
        predictions[name] = {
            'prediction': prediction,
            'confidence': probabilities[0] if prediction == 'camera' else probabilities[1]
        }
    
    return predictions, None

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scripts/predict.py <pcap_file>")
        sys.exit(1)
    
    predictions, error = predict_flow(sys.argv[1])
    
    if error:
        print(f"Error: {error}")
    else:
        print("\nPredictions:")
        for model, result in predictions.items():
            print(f"{model}: {result['prediction'].upper()} ({result['confidence']:.1%})")
"""
train_model.py - Train and Compare Multiple ML Models
======================================================

Trains three classifiers and compares their performance:
1. Random Forest
2. Support Vector Machine (SVM)
3. K-Nearest Neighbors (KNN)

This version adds PNG outputs (matplotlib only) for:
 - Confusion matrices (per model)
 - Model comparison (Accuracy vs F1)
 - Random Forest feature importances

Usage:
    python scripts/train_model.py

Output:
    - Saves all models to data/models/
    - Saves plots to data/plots/
    - Prints a comparison table
    - Displays confusion matrices
    - Reports feature importance
"""

import json
import pandas as pd
import numpy as np
from pathlib import Path
import pickle
import time
import os

from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score
)
from sklearn.preprocessing import StandardScaler

import matplotlib.pyplot as plt


class ModelTrainer:
    """Train and compare ML models for binary camera classification."""

    def __init__(self, features_json_path):
        self.features_json = Path(features_json_path)
        self.models_dir = Path(__file__).parent.parent / "data" / "models"
        self.models_dir.mkdir(parents=True, exist_ok=True)

        self.plots_dir = self.models_dir.parent / "plots"
        self.plots_dir.mkdir(parents=True, exist_ok=True)

        # -------------------------
        # MODELS (KNN added)
        # -------------------------
        self.models = {
            'Random Forest': {
                'model': RandomForestClassifier(
                    n_estimators=100,
                    max_depth=20,
                    min_samples_split=5,
                    random_state=42,
                    n_jobs=-1
                ),
                'filename': 'random_forest_model.pkl',
                'needs_scaling': False
            },
            'SVM': {
                'model': SVC(
                    kernel='rbf',
                    C=10.0,
                    gamma='scale',
                    probability=True,
                    random_state=42
                ),
                'filename': 'svm_model.pkl',
                'needs_scaling': True
            },
            'KNN': {
                'model': KNeighborsClassifier(
                    n_neighbors=5,
                    weights='uniform',
                    metric='minkowski',
                    p=2
                ),
                'filename': 'knn_model.pkl',
                'needs_scaling': True
            }
        }

        self.results = {}

    def save_plot(self, fig, filename):
        safe_name = filename.replace(" ", "_")
        path = self.plots_dir / safe_name
        fig.savefig(path, dpi=300, bbox_inches='tight')
        plt.close(fig)
        print(f"Saved plot: {path}")

    def load_data(self):
        if not self.features_json.exists():
            raise FileNotFoundError(
                f"Features file not found: {self.features_json}\n"
                "Run: python scripts/parse_pcap.py"
            )

        print(f"Loading features from {self.features_json.name}...")
        with open(self.features_json, 'r') as f:
            dataset = json.load(f)

        if len(dataset) < 10:
            print(f"WARNING: Only {len(dataset)} samples found.")

        df = pd.DataFrame(dataset)
        print(f"Loaded {len(df)} samples")

        if 'label' not in df.columns:
            raise KeyError("Dataset must contain 'label' field.")

        print(f"Class distribution: {df['label'].value_counts().to_dict()}")
        return df

    def prepare_data(self, df):
        drop_cols = ['label']
        if 'filename' in df.columns:
            drop_cols.append('filename')

        X = df.drop(drop_cols, axis=1)
        y = df['label']
        X = X.fillna(0)

        stratify_param = y if len(y.unique()) > 1 and all(y.value_counts() > 1) else None

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=stratify_param
        )

        print("\nDataset split:")
        print(f"  Training: {len(X_train)} samples")
        print(f"  Testing:  {len(X_test)} samples")

        return X_train, X_test, y_train, y_test

    def train_model(self, name, config, X_train, X_test, y_train, y_test):
        print("\n" + "="*60)
        print(f"Training: {name}")
        print("="*60)

        model = config['model']

        if config['needs_scaling']:
            scaler = StandardScaler()
            X_train_scaled = scaler.fit_transform(X_train)
            X_test_scaled = scaler.transform(X_test)
            config['scaler'] = scaler
        else:
            X_train_scaled = X_train.values
            X_test_scaled = X_test.values
            config['scaler'] = None

        start_time = time.time()
        model.fit(X_train_scaled, y_train)
        train_time = time.time() - start_time

        start_time = time.time()
        y_pred = model.predict(X_test_scaled)
        predict_time = time.time() - start_time

        pos_label = 'camera' if 'camera' in y_test.unique() else None

        try:
            accuracy = accuracy_score(y_test, y_pred)
            if pos_label:
                precision = precision_score(y_test, y_pred, pos_label=pos_label)
                recall = recall_score(y_test, y_pred, pos_label=pos_label)
                f1 = f1_score(y_test, y_pred, pos_label=pos_label)
            else:
                precision = precision_score(y_test, y_pred, average='binary')
                recall = recall_score(y_test, y_pred, average='binary')
                f1 = f1_score(y_test, y_pred, average='binary')
        except Exception:
            accuracy = accuracy_score(y_test, y_pred)
            precision = recall = f1 = 0.0

        X_full = pd.concat([X_train, X_test])
        y_full = pd.concat([y_train, y_test])

        if config['needs_scaling']:
            X_full_scaled = config['scaler'].fit_transform(X_full)
        else:
            X_full_scaled = X_full.values

        cv = min(5, max(2, len(X_full) // 2))
        try:
            cv_scores = cross_val_score(model, X_full_scaled, y_full, cv=cv)
            cv_mean = cv_scores.mean()
            cv_std = cv_scores.std()
        except Exception:
            cv_mean = cv_std = 0.0

        self.results[name] = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'cv_mean': cv_mean,
            'cv_std': cv_std,
            'train_time': train_time,
            'predict_time': predict_time,
            'y_test': y_test,
            'y_pred': y_pred,
            'model': model,
            'scaler': config['scaler']
        }

        print("\nResults:")
        print(f"  Accuracy:      {accuracy:.2%}")
        print(f"  Precision:     {precision:.2%}")
        print(f"  Recall:        {recall:.2%}")
        print(f"  F1-Score:      {f1:.2%}")
        print(f"  CV Mean:       {cv_mean:.2%}")
        print(f"  CV Std Dev:    {cv_std:.2%}")
        print(f"  Train Time:    {train_time:.3f}s")
        print(f"  Predict Time:  {predict_time:.4f}s")

        cm = confusion_matrix(y_test, y_pred)

        fig, ax = plt.subplots(figsize=(6, 5))
        im = ax.imshow(cm, interpolation='nearest', cmap='Blues')
        ax.set_title(f"Confusion Matrix - {name}")
        plt.colorbar(im, ax=ax)

        labels = list(pd.Series(y_test).unique())
        ax.set_xticks(np.arange(len(labels)))
        ax.set_yticks(np.arange(len(labels)))
        ax.set_xticklabels(labels, rotation=45)
        ax.set_yticklabels(labels)

        thresh = cm.max() / 2. if cm.max() != 0 else 0.5
        for i in range(cm.shape[0]):
            for j in range(cm.shape[1]):
                ax.text(
                    j, i, int(cm[i, j]),
                    ha="center", va="center",
                    color="white" if cm[i, j] > thresh else "black"
                )

        ax.set_ylabel('Actual')
        ax.set_xlabel('Predicted')
        fig.tight_layout()

        plot_name = f"confusion_matrix_{name.lower().replace(' ', '_')}.png"
        self.save_plot(fig, plot_name)

        model_path = self.models_dir / config['filename']
        feature_names = X_train.columns.tolist()
        model_data = {
            'model': model,
            'scaler': config['scaler'],
            'feature_names': feature_names
        }

        with open(model_path, 'wb') as f:
            pickle.dump(model_data, f)

        print(f"\nSaved model to {model_path}")
        return model

    def print_comparison(self):
        print("\n" + "="*80)
        print("MODEL COMPARISON")
        print("="*80 + "\n")

        comparison_data = []
        for name, results in self.results.items():
            comparison_data.append({
                'Model': name,
                'Accuracy': f"{results['accuracy']:.2%}",
                'Precision': f"{results['precision']:.2%}",
                'Recall': f"{results['recall']:.2%}",
                'F1-Score': f"{results['f1']:.2%}",
                'CV Score': f"{results['cv_mean']:.2%}",
                'Train Time': f"{results['train_time']:.3f}s",
                'Predict Time': f"{results['predict_time']:.4f}s"
            })

        df_comparison = pd.DataFrame(comparison_data)
        print(df_comparison.to_string(index=False))

        models = list(self.results.keys())
        accuracy = [self.results[m]['accuracy'] for m in models]
        f1 = [self.results[m]['f1'] for m in models]

        x = np.arange(len(models))
        width = 0.35

        fig, ax = plt.subplots(figsize=(8, 5))
        bars1 = ax.bar(x - width/2, accuracy, width, label='Accuracy')
        bars2 = ax.bar(x + width/2, f1, width, label='F1-Score')

        ax.set_xticks(x)
        ax.set_xticklabels(models, rotation=30, ha='right')
        ax.set_ylabel("Score")
        ax.set_ylim(0, 1)
        ax.set_title("Model Performance Comparison")
        ax.legend()

        for barset in (bars1, bars2):
            for bar in barset:
                h = bar.get_height()
                ax.annotate(
                    f"{h:.2%}",
                    xy=(bar.get_x() + bar.get_width() / 2, h),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha='center', va='bottom', fontsize=8
                )

        fig.tight_layout()
        self.save_plot(fig, "model_performance_comparison.png")

        print("\n" + "="*80)
        print("BEST MODELS BY METRIC")
        print("="*80 + "\n")

        metrics = ['accuracy', 'precision', 'recall', 'f1', 'cv_mean']
        metric_names = ['Accuracy', 'Precision', 'Recall', 'F1-Score', 'CV Score']

        for metric, label in zip(metrics, metric_names):
            try:
                m = max(self.results.items(), key=lambda x: x[1][metric])
                print(f"{label:12s}: {m[0]:20s} ({m[1][metric]:.2%})")
            except Exception:
                print(f"{label:12s}: No valid results.")

        print("\n" + "="*80)
        print("RECOMMENDATION")
        print("="*80 + "\n")

        try:
            best_model = max(self.results.items(), key=lambda x: x[1]['f1'])
            print(f"Recommended model: {best_model[0]}")
            print(f"  F1-Score: {best_model[1]['f1']:.2%}")
            print(f"  CV Score: {best_model[1]['cv_mean']:.2%}")
        except Exception:
            print("No recommendation available.")

        try:
            fastest = min(self.results.items(), key=lambda x: x[1]['predict_time'])
            print(f"\nFastest model: {fastest[0]}")
            print(f"  Prediction time: {fastest[1]['predict_time']:.4f}s")
        except Exception:
            print("No timing information available.")

    def print_feature_importance(self, X_train):
        print("\n" + "="*80)
        print("FEATURE IMPORTANCE (Random Forest)")
        print("="*80 + "\n")

        if 'Random Forest' not in self.results:
            print("Random Forest results not found.")
            return

        rf = self.results['Random Forest']['model']

        if not hasattr(rf, 'feature_importances_'):
            print("Random Forest does not expose feature_importances_.")
            return

        importance = pd.DataFrame({
            'Feature': X_train.columns,
            'Importance': rf.feature_importances_
        }).sort_values('Importance', ascending=False)

        print("Top 15 Features:")
        print(f"{'Rank':<6}{'Feature':<35}{'Importance'}")
        print("-" * 55)

        for i, (_, row) in enumerate(importance.head(15).iterrows(), 1):
            print(f"{i:<6}{row['Feature']:<35}{row['Importance']:.6f}")

        categories = {
            'PLD Pattern': ['pld_mean', 'pld_std', 'pld_median', 'pld_alternation', 'pld_hist'],
            'PLD Stability': ['pld_stability', 'pld_window'],
            'Bandwidth': ['bandwidth_mean', 'bandwidth_std', 'bandwidth_cv'],
            'Duration Field': ['duration_mean', 'duration_std', 'duration_mode', 'duration_entropy']
        }

        print("\nFeature Category Contributions:")
        for category, keys in categories.items():
            pattern = '|'.join(keys)
            total = importance[importance['Feature'].str.contains(pattern)]['Importance'].sum()
            print(f"{category:<20s}: {total:.4f}")

        top_n = min(20, len(importance))
        top_features = importance.head(top_n).iloc[::-1]

        fig, ax = plt.subplots(figsize=(10, max(4, 0.3 * top_n)))
        y_pos = np.arange(len(top_features))
        ax.barh(y_pos, top_features['Importance'].values)
        ax.set_yticks(y_pos)
        ax.set_yticklabels(top_features['Feature'].values)
        ax.set_xlabel("Importance")
        ax.set_title("Top Feature Importances (Random Forest)")

        fig.tight_layout()
        self.save_plot(fig, "feature_importance_random_forest.png")

    def train_all(self):
        print("\n" + "="*80)
        print("CAMERA FLOW CLASSIFIER - TRAINING")
        print("="*80 + "\n")

        df = self.load_data()
        X_train, X_test, y_train, y_test = self.prepare_data(df)

        for name, config in self.models.items():
            self.train_model(name, config, X_train, X_test, y_train, y_test)

        self.print_comparison()
        self.print_feature_importance(X_train)

        print("\n" + "="*80)
        print("TRAINING COMPLETE")
        print("="*80 + "\n")
        print(f"Models saved to: {self.models_dir}")
        print(f"Plots saved to: {self.plots_dir}")
        print("Next steps:")
        print("  python scripts/predict.py <pcap_file>")
        print()

def main():
    project_root = Path(__file__).parent.parent
    features_json = project_root / "data" / "processed" / "features.json"

    trainer = ModelTrainer(features_json)
    trainer.train_all()

if __name__ == "__main__":
    main()

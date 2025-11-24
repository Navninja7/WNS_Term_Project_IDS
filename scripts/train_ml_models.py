#!/usr/bin/env python3


import pandas as pd
import numpy as np
import sys
import pickle
import json
from pathlib import Path
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

# ML libraries
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score, roc_curve
)

# ML Models
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, AdaBoostClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from xgboost import XGBClassifier


import matplotlib
matplotlib.use('Agg')  
import matplotlib.pyplot as plt
import seaborn as sns

class IDSModelTrainer:
    def __init__(self, input_dir, output_dir):
        self.input_dir = Path(input_dir)
        self.output_dir = Path(output_dir)
        self.models_dir = self.output_dir / 'trained_models'
        self.plots_dir = self.output_dir / 'plots'
        self.results_dir = self.output_dir / 'results'
        
        
        for d in [self.models_dir, self.plots_dir, self.results_dir]:
            d.mkdir(parents=True, exist_ok=True)
        
        self.attack_names = {
            0: 'Normal',
            1: 'Deauth',
            2: 'Disass',
            3: 'ReAssoc',
            4: 'Rogue_AP',
            5: 'Krack',
            6: 'Kr00k',
            7: 'Evil_Twin',
            8: 'SQL_Injection',
            9: 'SSH',
            10: 'Malware',
            11: 'SSDP',
            12: 'Botnet',
            13: 'Website_spoofing'
        }
        
        self.results = {}
        
    def load_and_combine_data(self):

        print("\n" + "="*70)
        print("LOADING DATASETS")
        print("="*70)
        
        csv_files = sorted(self.input_dir.glob("*_labeled.csv"))
        
        if not csv_files:
            print("✗ No labeled CSV files found!")
            sys.exit(1)
        
        print(f"Found {len(csv_files)} labeled CSV files")
        
        dataframes = []
        total_samples = 0
        label_distribution = {}
        
        for csv_file in csv_files:
            print(f"  Loading: {csv_file.name}")
            try:
                df = pd.read_csv(csv_file, low_memory=False)
                samples = len(df)
                total_samples += samples
                
                
                for label, count in df['label'].value_counts().items():
                    label_name = self.attack_names.get(int(label), f'Unknown_{label}')
                    label_distribution[label_name] = label_distribution.get(label_name, 0) + count
                
                dataframes.append(df)
                print(f"    Loaded {samples:,} samples")
                
            except Exception as e:
                print(f"    ✗ Error loading {csv_file.name}: {str(e)}")
        
        if not dataframes:
            print("✗ No data loaded!")
            sys.exit(1)
        
        
        print(f"\nCombining {len(dataframes)} datasets...")
        combined_df = pd.concat(dataframes, ignore_index=True)
        
        print(f"\n Combined Dataset:")
        print(f"  Total samples: {len(combined_df):,}")
        print(f"  Total features: {len(combined_df.columns) - 1}")
        print(f"\n  Label Distribution:")
        for label, count in sorted(label_distribution.items()):
            pct = count / total_samples * 100
            print(f"    {label:20s}: {count:>10,} ({pct:>5.2f}%)")
        
        return combined_df
    
    def preprocess_data(self, df):
        
        print("\n" + "="*70)
        print("PREPROCESSING DATA")
        print("="*70)
        
        
        X = df.drop('label', axis=1)
        y = df['label']
        
        print(f"Original shape: {X.shape}")
        
        
        print("\nHandling missing values...")
        missing_before = X.isnull().sum().sum()
        X = X.fillna(0)
        print(f"  Filled {missing_before:,} missing values with 0")
        
        
        print("\nEncoding categorical features...")
        object_cols = X.select_dtypes(include=['object']).columns
        if len(object_cols) > 0:
            print(f"  Found {len(object_cols)} categorical columns")
            for col in object_cols:
                X[col] = pd.factorize(X[col])[0]
            print(f"   Encoded {len(object_cols)} columns")
        
        
        print("\nRemoving constant features...")
        constant_cols = [col for col in X.columns if X[col].nunique() == 1]
        if constant_cols:
            X = X.drop(columns=constant_cols)
            print(f"  Removed {len(constant_cols)} constant features")
        
        
        print("\nRemoving highly correlated features...")
        correlation_threshold = 0.95
        corr_matrix = X.corr().abs()
        upper_triangle = corr_matrix.where(
            np.triu(np.ones(corr_matrix.shape), k=1).astype(bool)
        )
        to_drop = [col for col in upper_triangle.columns if any(upper_triangle[col] > correlation_threshold)]
        if to_drop:
            X = X.drop(columns=to_drop)
            print(f"  Removed {len(to_drop)} highly correlated features")
        
        print(f"\n Preprocessed shape: {X.shape}")
        
        return X, y
    
    def split_data(self, X, y, test_size=0.3):
        
        print("\n" + "="*70)
        print("SPLITTING DATA")
        print("="*70)
        
        print(f"Test size: {test_size*100}%")
        print(f"Train size: {(1-test_size)*100}%")
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        
        print(f"\nTraining set: {len(X_train):,} samples")
        print(f"Testing set:  {len(X_test):,} samples")
        
        
        print("\nClass distribution in splits:")
        print("  Training set:")
        for label, count in y_train.value_counts().sort_index().items():
            label_name = self.attack_names.get(int(label), f'Label_{label}')
            print(f"    {label_name:20s}: {count:>8,}")
        
        print("  Testing set:")
        for label, count in y_test.value_counts().sort_index().items():
            label_name = self.attack_names.get(int(label), f'Label_{label}')
            print(f"    {label_name:20s}: {count:>8,}")
        
        return X_train, X_test, y_train, y_test
    
    def scale_features(self, X_train, X_test):
        
        print("\n" + "="*70)
        print("SCALING FEATURES")
        print("="*70)
        
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        
        scaler_path = self.models_dir / 'scaler.pkl'
        with open(scaler_path, 'wb') as f:
            pickle.dump(scaler, f)
        
        print(f" Features scaled using StandardScaler")
        print(f" Scaler saved to: {scaler_path}")
        
        return X_train_scaled, X_test_scaled, scaler
    
    def get_models(self):
        models = {
           
            'Random Forest': RandomForestClassifier(
                n_estimators=100,
                max_depth=20,
                random_state=42,
                n_jobs=-1
            )
        }
        
        return models
    
    def train_and_evaluate_model(self, name, model, X_train, X_test, y_train, y_test):
        
        print(f"\n{'='*70}")
        print(f"TRAINING: {name}")
        print('='*70)
        
        
        print("Training...")
        start_time = datetime.now()
        model.fit(X_train, y_train)
        train_time = (datetime.now() - start_time).total_seconds()
        print(f" Training completed in {train_time:.2f} seconds")
        
        
        print("Making predictions...")
        y_pred_train = model.predict(X_train)
        y_pred_test = model.predict(X_test)
        
        
        print("Calculating metrics...")
        
        
        train_acc = accuracy_score(y_train, y_pred_train)
        test_acc = accuracy_score(y_test, y_pred_test)
        
        precision = precision_score(y_test, y_pred_test, average='weighted', zero_division=0)
        recall = recall_score(y_test, y_pred_test, average='weighted', zero_division=0)
        f1 = f1_score(y_test, y_pred_test, average='weighted', zero_division=0)
        
        
        cm = confusion_matrix(y_test, y_pred_test)
        
        
        results = {
            'model_name': name,
            'train_accuracy': train_acc,
            'test_accuracy': test_acc,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'training_time': train_time,
            'confusion_matrix': cm.tolist()
        }
        
        
        print(f"\n{name} Results:")
        print(f"  Training Accuracy:   {train_acc:.4f}")
        print(f"  Testing Accuracy:    {test_acc:.4f}")
        print(f"  Precision (weighted): {precision:.4f}")
        print(f"  Recall (weighted):    {recall:.4f}")
        print(f"  F1-Score (weighted):  {f1:.4f}")
        
        
        model_path = self.models_dir / f"{name.replace(' ', '_').lower()}_model.pkl"
        with open(model_path, 'wb') as f:
            pickle.dump(model, f)
        print(f"\n Model saved to: {model_path}")
        
        
        report = classification_report(
            y_test, y_pred_test,
            target_names=[self.attack_names.get(i, f'Class_{i}') for i in sorted(y_test.unique())],
            output_dict=True,
            zero_division=0
        )
        
        report_path = self.results_dir / f"{name.replace(' ', '_').lower()}_report.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        return results, cm
    
    def plot_comparison(self):
        
        print("\n" + "="*70)
        print("GENERATING COMPARISON PLOTS")
        print("="*70)
        
        if not self.results:
            print("No results to plot!")
            return
        
        
        models = list(self.results.keys())
        metrics = ['test_accuracy', 'precision', 'recall', 'f1_score']
        metric_names = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
        
        
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        fig.suptitle('ML Models Performance Comparison', fontsize=16, fontweight='bold')
        
        for idx, (metric, metric_name) in enumerate(zip(metrics, metric_names)):
            ax = axes[idx // 2, idx % 2]
            
            values = [self.results[model][metric] for model in models]
            colors = plt.cm.viridis(np.linspace(0, 1, len(models)))
            
            bars = ax.bar(range(len(models)), values, color=colors)
            ax.set_xlabel('Models', fontweight='bold')
            ax.set_ylabel(metric_name, fontweight='bold')
            ax.set_title(f'{metric_name} Comparison', fontweight='bold')
            ax.set_xticks(range(len(models)))
            ax.set_xticklabels(models, rotation=45, ha='right')
            ax.set_ylim([0, 1.1])
            ax.grid(axis='y', alpha=0.3)
            
            
            for bar, value in zip(bars, values):
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2., height,
                       f'{value:.3f}',
                       ha='center', va='bottom', fontsize=9)
        
        plt.tight_layout()
        comparison_path = self.plots_dir / 'models_comparison.png'
        plt.savefig(comparison_path, dpi=300, bbox_inches='tight')
        plt.close()
        print(f" Comparison plot saved: {comparison_path}")
        
        
        self.plot_metrics_table()
        
        
        self.plot_training_time()
    
    def plot_metrics_table(self):
        
        models = list(self.results.keys())
        metrics = ['test_accuracy', 'precision', 'recall', 'f1_score']
        metric_names = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
        
        
        data = []
        for model in models:
            row = [model] + [f"{self.results[model][m]:.4f}" for m in metrics]
            data.append(row)
        
        
        fig, ax = plt.subplots(figsize=(12, len(models) * 0.6 + 2))
        ax.axis('tight')
        ax.axis('off')
        
        table = ax.table(
            cellText=data,
            colLabels=['Model'] + metric_names,
            cellLoc='center',
            loc='center',
            colWidths=[0.3, 0.175, 0.175, 0.175, 0.175]
        )
        
        table.auto_set_font_size(False)
        table.set_fontsize(10)
        table.scale(1, 2)
        
        
        for i in range(len(metric_names) + 1):
            table[(0, i)].set_facecolor('#4CAF50')
            table[(0, i)].set_text_props(weight='bold', color='white')
        
        
        for i in range(1, len(data) + 1):
            for j in range(len(metric_names) + 1):
                if i % 2 == 0:
                    table[(i, j)].set_facecolor('#f0f0f0')
        
        plt.title('Detailed Performance Metrics', fontsize=14, fontweight='bold', pad=20)
        
        table_path = self.plots_dir / 'metrics_table.png'
        plt.savefig(table_path, dpi=300, bbox_inches='tight')
        plt.close()
        print(f" Metrics table saved: {table_path}")
    
    def plot_training_time(self):
        
        models = list(self.results.keys())
        times = [self.results[model]['training_time'] for model in models]
        
        fig, ax = plt.subplots(figsize=(12, 6))
        colors = plt.cm.plasma(np.linspace(0, 1, len(models)))
        bars = ax.barh(models, times, color=colors)
        
        ax.set_xlabel('Training Time (seconds)', fontweight='bold')
        ax.set_ylabel('Models', fontweight='bold')
        ax.set_title('Training Time Comparison', fontweight='bold', fontsize=14)
        ax.grid(axis='x', alpha=0.3)
        
        
        for bar, time in zip(bars, times):
            width = bar.get_width()
            ax.text(width, bar.get_y() + bar.get_height()/2.,
                   f'{time:.2f}s',
                   ha='left', va='center', fontsize=10, fontweight='bold')
        
        plt.tight_layout()
        time_path = self.plots_dir / 'training_time_comparison.png'
        plt.savefig(time_path, dpi=300, bbox_inches='tight')
        plt.close()
        print(f" Training time plot saved: {time_path}")
    
    def plot_confusion_matrices(self, confusion_matrices):
        
        print("\nGenerating confusion matrices...")
        
        n_models = len(confusion_matrices)
        cols = 3
        rows = (n_models + cols - 1) // cols
        
        fig, axes = plt.subplots(rows, cols, figsize=(18, 6*rows))
        if n_models == 1:
            axes = [axes]
        else:
            axes = axes.flatten()
        
        for idx, (model_name, cm) in enumerate(confusion_matrices.items()):
            ax = axes[idx]
            
            
            cm_norm = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
            
            sns.heatmap(cm_norm, annot=True, fmt='.2f', cmap='Blues',
                       ax=ax, cbar_kws={'label': 'Proportion'})
            
            ax.set_title(f'{model_name}\nConfusion Matrix (Normalized)',
                        fontweight='bold')
            ax.set_ylabel('True Label', fontweight='bold')
            ax.set_xlabel('Predicted Label', fontweight='bold')
        
        
        for idx in range(n_models, len(axes)):
            axes[idx].axis('off')
        
        plt.tight_layout()
        cm_path = self.plots_dir / 'confusion_matrices.png'
        plt.savefig(cm_path, dpi=300, bbox_inches='tight')
        plt.close()
        print(f" Confusion matrices saved: {cm_path}")
    
    def save_summary(self):
        
        summary = {
            'timestamp': datetime.now().isoformat(),
            'models_trained': len(self.results),
            'results': self.results
        }
        
        summary_path = self.results_dir / 'training_summary.json'
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"\n Training summary saved: {summary_path}")
    
    def run(self):
        print("\n" + "="*70)
        print("IDS ML MODEL TRAINING PIPELINE")
        print("="*70)
        
        
        df = self.load_and_combine_data()
        
        
        X, y = self.preprocess_data(df)
        
        
        X_train, X_test, y_train, y_test = self.split_data(X, y)
        
        
        X_train_scaled, X_test_scaled, scaler = self.scale_features(X_train, X_test)
        
        
        models = self.get_models()
        
        print(f"\n" + "="*70)
        print(f"TRAINING {len(models)} MODELS")
        print("="*70)
        
        confusion_matrices = {}
        
        
        for name, model in models.items():
            results, cm = self.train_and_evaluate_model(
                name, model, X_train_scaled, X_test_scaled, y_train, y_test
            )
            self.results[name] = results
            confusion_matrices[name] = cm
        
        
        self.plot_comparison()
        self.plot_confusion_matrices(confusion_matrices)
        
        
        self.save_summary()
        
        
        print("\n" + "="*70)
        print("TRAINING COMPLETE!")
        print("="*70)
        print(f" Trained {len(self.results)} models")
        print(f" Models saved to: {self.models_dir}")
        print(f" Plots saved to: {self.plots_dir}")
        print(f" Results saved to: {self.results_dir}")
        
        
        best_model = max(self.results.items(), key=lambda x: x[1]['test_accuracy'])
        print(f"\n🏆 Best Model: {best_model[0]}")
        print(f"   Accuracy: {best_model[1]['test_accuracy']:.4f}")
        print(f"   F1-Score: {best_model[1]['f1_score']:.4f}")

def main():
    if len(sys.argv) != 3:
        print("="*70)
        print("IDS ML Model Training Script")
        print("="*70)
        print("\nUsage:")
        print("  python train_ml_models.py <labeled_csv_dir> <output_dir>")
        print("\nExample:")
        print("  python train_ml_models.py ./labeled_csvs ./models")
        print("\nOutput:")
        print("  - Trained models (.pkl files)")
        print("  - Performance plots")
        print("  - Metrics and reports")
        print("="*70)
        sys.exit(1)
    
    input_dir = sys.argv[1]
    output_dir = sys.argv[2]
    
    trainer = IDSModelTrainer(input_dir, output_dir)
    trainer.run()

if __name__ == "__main__":
    main()
"""
Model training script for CyberGuard threat detection.
Trains machine learning models for behavioral analysis and threat detection.
"""

import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow import keras
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import pickle
import logging
from datetime import datetime
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatDetectionModel:
    """Machine learning model for threat detection."""
    
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.model_type = "random_forest"  # or "neural_network"
    
    def create_neural_network(self, input_dim: int) -> keras.Model:
        """Create a neural network model for threat detection."""
        model = keras.Sequential([
            keras.layers.Dense(128, activation='relu', input_shape=(input_dim,)),
            keras.layers.Dropout(0.3),
            keras.layers.Dense(64, activation='relu'),
            keras.layers.Dropout(0.3),
            keras.layers.Dense(32, activation='relu'),
            keras.layers.Dense(3, activation='softmax')  # 3 classes: low, medium, high threat
        ])
        
        model.compile(
            optimizer='adam',
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    def create_random_forest(self) -> RandomForestClassifier:
        """Create a random forest classifier."""
        return RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight='balanced'
        )
    
    def load_training_data(self, data_path: str) -> tuple:
        """Load and preprocess training data."""
        # Placeholder for actual data loading
        # In production, this would load from database or files
        
        # Generate synthetic training data for demonstration
        np.random.seed(42)
        n_samples = 1000
        
        # Feature columns (simulated behavioral features)
        features = np.random.randn(n_samples, 20)
        
        # Labels: 0=low, 1=medium, 2=high threat
        labels = np.random.choice([0, 1, 2], size=n_samples, p=[0.7, 0.2, 0.1])
        
        # Add some patterns to make it learnable
        features[labels == 2, :5] += 2.0  # High threat patterns
        features[labels == 1, 5:10] += 1.0  # Medium threat patterns
        
        return features, labels
    
    def preprocess_data(self, X: np.ndarray, y: np.ndarray = None) -> tuple:
        """Preprocess the training data."""
        # Scale features
        if y is not None:
            X_scaled = self.scaler.fit_transform(X)
            y_encoded = self.label_encoder.fit_transform(y)
            return X_scaled, y_encoded
        else:
            return self.scaler.transform(X), None
    
    def train(self, data_path: str = None, model_type: str = "random_forest"):
        """Train the threat detection model."""
        logger.info("Loading training data...")
        X, y = self.load_training_data(data_path)
        
        logger.info("Preprocessing data...")
        X_processed, y_processed = self.preprocess_data(X, y)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_processed, y_processed, test_size=0.2, random_state=42
        )
        
        self.model_type = model_type
        
        if model_type == "neural_network":
            logger.info("Training neural network...")
            self.model = self.create_neural_network(X_train.shape[1])
            
            history = self.model.fit(
                X_train, y_train,
                epochs=50,
                batch_size=32,
                validation_split=0.2,
                verbose=1
            )
            
            # Evaluate
            test_loss, test_acc = self.model.evaluate(X_test, y_test, verbose=0)
            logger.info(f"Neural Network Test Accuracy: {test_acc:.4f}")
            
        else:  # random_forest
            logger.info("Training Random Forest...")
            self.model = self.create_random_forest()
            self.model.fit(X_train, y_train)
            
            # Evaluate
            y_pred = self.model.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            logger.info(f"Random Forest Test Accuracy: {accuracy:.4f}")
            logger.info("\nClassification Report:\n" + classification_report(y_test, y_pred))
    
    def predict(self, features: np.ndarray) -> tuple:
        """Predict threat level for given features."""
        if self.model is None:
            raise ValueError("Model not trained. Call train() first.")
        
        # Preprocess features
        X_processed, _ = self.preprocess_data(features)
        
        if self.model_type == "neural_network":
            predictions = self.model.predict(X_processed)
            threat_level = np.argmax(predictions, axis=1)
            confidence = np.max(predictions, axis=1)
        else:
            predictions = self.model.predict_proba(X_processed)
            threat_level = np.argmax(predictions, axis=1)
            confidence = np.max(predictions, axis=1)
        
        # Convert back to original labels
        threat_labels = self.label_encoder.inverse_transform(threat_level)
        
        return threat_labels, confidence
    
    def save_model(self, model_path: str):
        """Save the trained model and preprocessing objects."""
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        
        if self.model_type == "neural_network":
            self.model.save(model_path)
        else:
            with open(model_path, 'wb') as f:
                pickle.dump(self.model, f)
        
        # Save preprocessing objects
        preprocessing_path = model_path.replace('.h5', '_preprocessing.pkl').replace('.pkl', '_preprocessing.pkl')
        with open(preprocessing_path, 'wb') as f:
            pickle.dump({
                'scaler': self.scaler,
                'label_encoder': self.label_encoder,
                'model_type': self.model_type
            }, f)
        
        logger.info(f"Model saved to {model_path}")
    
    def load_model(self, model_path: str):
        """Load a trained model and preprocessing objects."""
        preprocessing_path = model_path.replace('.h5', '_preprocessing.pkl').replace('.pkl', '_preprocessing.pkl')
        
        if not os.path.exists(preprocessing_path):
            raise FileNotFoundError(f"Preprocessing file not found: {preprocessing_path}")
        
        # Load preprocessing
        with open(preprocessing_path, 'rb') as f:
            preprocessing = pickle.load(f)
        
        self.scaler = preprocessing['scaler']
        self.label_encoder = preprocessing['label_encoder']
        self.model_type = preprocessing['model_type']
        
        # Load model
        if self.model_type == "neural_network":
            self.model = keras.models.load_model(model_path)
        else:
            with open(model_path, 'rb') as f:
                self.model = pickle.load(f)
        
        logger.info(f"Model loaded from {model_path}")

def main():
    """Main training function."""
    model = ThreatDetectionModel()
    
    # Train the model
    model.train(model_type="random_forest")
    
    # Save the model
    model_path = "../models/threat_detection_model.pkl"
    model.save_model(model_path)
    
    # Test prediction
    test_features = np.random.randn(5, 20)
    threats, confidences = model.predict(test_features)
    
    logger.info("Sample predictions:")
    for i, (threat, confidence) in enumerate(zip(threats, confidences)):
        logger.info(f"Sample {i+1}: Threat level {threat}, Confidence {confidence:.3f}")

if __name__ == "__main__":
    main()

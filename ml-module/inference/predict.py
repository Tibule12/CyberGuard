"""
Inference module for CyberGuard threat detection.
Handles real-time threat prediction using trained ML models.
"""

import numpy as np
from typing import Dict, Any, List, Tuple
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class ThreatPredictor:
    """Real-time threat prediction using ML models."""
    
    def __init__(self, model_path: str = None):
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.model_type = None
        
        if model_path:
            self.load_model(model_path)
    
    def load_model(self, model_path: str):
        """Load trained model and preprocessing objects."""
        # Placeholder for actual model loading
        # This would load the actual trained model in production
        logger.info(f"Loading model from {model_path}")
        
        # Simulate model loading
        self.model_type = "random_forest"
        logger.info("Model loaded successfully")
    
    def extract_features(self, event_data: Dict[str, Any]) -> np.ndarray:
        """Extract features from event data for ML prediction."""
        # Placeholder for feature extraction
        # This would convert raw event data into features for the ML model
        
        # Example feature extraction (simplified)
        features = []
        
        # Process-related features
        if 'processes' in event_data:
            process_count = len(event_data['processes'])
            features.extend([process_count, process_count / 100])  # Normalized
        
        # Network-related features
        if 'network_connections' in event_data:
            conn_count = len(event_data['network_connections'])
            features.extend([conn_count, conn_count / 50])  # Normalized
        
        # System-related features
        if 'system_info' in event_data:
            sys_info = event_data['system_info']
            features.extend([
                sys_info.get('cpu_count', 0) / 16,  # Normalized
                sys_info.get('total_memory', 0) / (16 * 1024 * 1024 * 1024)  # Normalized to 16GB
            ])
        
        # Ensure we have exactly 20 features (matching training)
        while len(features) < 20:
            features.append(0.0)
        
        return np.array(features).reshape(1, -1)
    
    def predict_threat(self, event_data: Dict[str, Any]) -> Tuple[str, float]:
        """Predict threat level for given event data."""
        if self.model is None:
            # Fallback to rule-based detection if model not loaded
            return self._rule_based_detection(event_data), 0.8
        
        try:
            # Extract features
            features = self.extract_features(event_data)
            
            # Preprocess features (placeholder)
            # features_scaled = self.scaler.transform(features)
            
            # Make prediction (placeholder)
            # In production, this would use the actual loaded model
            threat_level = self._simulate_prediction(features)
            confidence = 0.85  # Simulated confidence
            
            return threat_level, confidence
            
        except Exception as e:
            logger.error(f"Prediction failed: {e}")
            return "unknown", 0.0
    
    def _simulate_prediction(self, features: np.ndarray) -> str:
        """Simulate ML prediction (placeholder)."""
        # Simple simulation based on feature values
        feature_sum = np.sum(features)
        
        if feature_sum > 5.0:
            return "high"
        elif feature_sum > 2.0:
            return "medium"
        else:
            return "low"
    
    def _rule_based_detection(self, event_data: Dict[str, Any]) -> str:
        """Fallback rule-based threat detection."""
        threats_detected = []
        
        # Check for suspicious processes
        if 'processes' in event_data:
            suspicious_processes = self._check_suspicious_processes(event_data['processes'])
            if suspicious_processes:
                threats_detected.append("suspicious_processes")
        
        # Check for unusual network activity
        if 'network_connections' in event_data:
            suspicious_network = self._check_suspicious_network(event_data['network_connections'])
            if suspicious_network:
                threats_detected.append("suspicious_network")
        
        # Determine threat level based on detected issues
        if threats_detected:
            if len(threats_detected) >= 2 or "suspicious_network" in threats_detected:
                return "high"
            else:
                return "medium"
        
        return "low"
    
    def _check_suspicious_processes(self, processes: List[Dict[str, Any]]) -> bool:
        """Check for suspicious processes."""
        suspicious_keywords = [
            'miner', 'backdoor', 'trojan', 'virus', 'malware', 
            'keylogger', 'ransomware', 'exploit', 'rootkit'
        ]
        
        for process in processes:
            name = process.get('name', '').lower()
            if any(keyword in name for keyword in suspicious_keywords):
                return True
        
        return False
    
    def _check_suspicious_network(self, connections: List[Dict[str, Any]]) -> bool:
        """Check for suspicious network connections."""
        suspicious_ports = [4444, 31337, 6667, 12345, 54321]  # Common malicious ports
        suspicious_ips = ['10.0.0.1']  # Example suspicious IPs
        
        for conn in connections:
            remote_addr = conn.get('remote_address')
            if remote_addr:
                # Check port
                if hasattr(remote_addr, 'port') and remote_addr.port in suspicious_ports:
                    return True
                # Check IP
                if hasattr(remote_addr, 'ip') and remote_addr.ip in suspicious_ips:
                    return True
        
        return False
    
    def batch_predict(self, events_data: List[Dict[str, Any]]) -> List[Tuple[str, float]]:
        """Predict threat levels for multiple events."""
        results = []
        for event_data in events_data:
            threat_level, confidence = self.predict_threat(event_data)
            results.append((threat_level, confidence))
        
        return results

# Global predictor instance
_predictor_instance = None

def get_predictor(model_path: str = None) -> ThreatPredictor:
    """Get or create threat predictor instance."""
    global _predictor_instance
    if _predictor_instance is None:
        _predictor_instance = ThreatPredictor(model_path)
    return _predictor_instance

def predict_threat_level(event_data: Dict[str, Any], model_path: str = None) -> Dict[str, Any]:
    """Convenience function for threat prediction."""
    predictor = get_predictor(model_path)
    threat_level, confidence = predictor.predict_threat(event_data)
    
    return {
        "threat_level": threat_level,
        "confidence": confidence,
        "timestamp": datetime.utcnow().isoformat(),
        "model_version": "0.1.0"
    }

if __name__ == "__main__":
    # Test the predictor
    test_event = {
        "processes": [
            {"name": "chrome.exe", "pid": 1234},
            {"name": "explorer.exe", "pid": 5678}
        ],
        "network_connections": [
            {"remote_address": "192.168.1.1:80", "status": "ESTABLISHED"}
        ],
        "system_info": {
            "cpu_count": 8,
            "total_memory": 17179869184  # 16GB
        }
    }
    
    result = predict_threat_level(test_event)
    print(f"Threat Level: {result['threat_level']}")
    print(f"Confidence: {result['confidence']}")

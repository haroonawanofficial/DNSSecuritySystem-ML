# historical_traffic_analysis.py

def analyze_historical_traffic(data, baseline):
    # Compare historical data with the baseline
    anomalies = []

    for entry in data:
        if entry not in baseline:
            anomalies.append(entry)

    return anomalies

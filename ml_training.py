# ml_training.py

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

def train_machine_learning_model(data):
    # Split data into features and target
    features = data.drop('target', axis=1)
    target = data['target']

    # Split data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(features, target, test_size=0.2)

    # Create and train a machine learning model (Random Forest for example)
    model = RandomForestClassifier()
    model.fit(X_train, y_train)

    return model

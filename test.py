import ember
import lightgbm as lgb

# Save the model

if __name__ == "__main__":
    #ember.create_vectorized_features(r"C:\Users\kshit\Desktop\amber\data\ember2018\ember2018")
    X_train, y_train, X_test, y_test = ember.read_vectorized_features(r"C:\Users\kshit\Desktop\amber\data\ember2018\ember2018")
    model = ember.train_model(r"C:\Users\kshit\Desktop\amber\data\ember2018\ember2018")
    model.save_model('malware_detector.txt')
    model.save_model('malware_detector.txt')
    import joblib

# Save model
    joblib.dump(model, 'malware_model.pkl')

# Load model
    model = joblib.load('malware_model.pkl')
    
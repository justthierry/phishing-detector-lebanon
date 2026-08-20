# Phishing URL Detector — AI for Lebanon

An ML-powered phishing URL detection system built to protect 
Lebanese users from cybersecurity threats.

Lebanon ranks 132nd globally in cybersecurity (NCSI, 2026) with 
a score of 21.67/100. This project applies machine learning to 
classify URLs as phishing or legitimate, addressing one of the 
most common cyber threats facing Lebanese users.

## Models Compared
                Model | Accuracy | Phishing Recall | F1-Score |
|---------------------|----------|-----------------|----------|
| Logistic Regression | 0.79     | 0.30            |     0.45 |
| Random Forest       | 0.86     | **0.70**        |      0.74|
| XGBoost             | 0.85     | 0.58            |     0.69 |
| MLP Neural Network  | 0.85     | 0.60            |     0.69 |
| Transformer         | 0.85     | 0.55            | 0.67     |

## Key Finding
URL entropy was the most predictive feature this is because phishing URLs are 
machine-generated and detectably more random than human-written URLs.

## Dataset
PhiUSIIL Phishing URL Dataset — 549,346 URLs (Kaggle)
- 392,924 legitimate URLs (71%)
- 156,422 phishing URLs (29%)

## How to Run
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the full notebook to train and save the model

# 3. Launch the detection agent
python detector.py
```

## Note on Model File
The trained model (rf_model.pkl) is not included due to file 
size (653MB). Run the notebook first to generate it.

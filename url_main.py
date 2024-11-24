import pandas as pd
import numpy as np
import sys
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

def sanitization(web):
    web = web.lower()
    token = []
    dot_token_slash = []
    raw_slash = str(web).split('/')
    for i in raw_slash:
        raw1 = str(i).split('-')
        slash_token = []
        for j in range(0, len(raw1)):
            raw2 = str(raw1[j]).split('.')
            slash_token = slash_token + raw2
        dot_token_slash = dot_token_slash + raw1 + slash_token
    token = list(set(dot_token_slash)) 
    if 'com' in token:
        token.remove('com')
    return token

def main(url):
    urls = [url]
    
    # Using whitelist filter
    whitelist = ['hackthebox.eu', 'root-me.org', 'gmail.com']
    s_url = [i for i in urls if i not in whitelist]

    # Loading the model
    model_file = "E:/project/Malware-Detection-using-Machine-learningss/Malware-Detection-using-Machine-learning/ML_Model/pickel_model.pkl"
    with open(model_file, 'rb') as f1:  
        lgr = pickle.load(f1)

    vectorizer_file = "E:/project/Malware-Detection-using-Machine-learningss/Malware-Detection-using-Machine-learning/ML_Model/pickel_vector.pkl"
    with open(vectorizer_file, 'rb') as f2:  
        vectorizer = pickle.load(f2)

    # Predicting
    x = vectorizer.transform(s_url)
    y_predict = lgr.predict(x)

    predict = list(y_predict)

    for site in whitelist:
        if site == url:
            predict = ['good']

    print(f"\nThe entered domain {url} is: {predict[0]}")
    
if __name__ == "__main__":
    # if len(sys.argv) > 1:
    #     url = sys.argv[1]
    #     main(url)
    # else:
    #     print("Error: No URL provided.")
    url='google.com'
    main(url)

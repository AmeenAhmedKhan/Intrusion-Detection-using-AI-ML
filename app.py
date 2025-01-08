from flask import Flask, request, render_template
import numpy as np
import pandas as pd
import subprocess
import os
import warnings
import pickle
from feature import FeatureExtraction

warnings.filterwarnings('ignore')

file = open("./pickle/model.pkl", "rb")
gbc = pickle.load(file)
file.close()

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        mode = request.form["mode"]
        input_data = request.form["input"]

        if mode == "url":
            obj = FeatureExtraction(input_data)
            x = np.array(obj.getFeaturesList()).reshape(1, 30)
            y_pred = gbc.predict(x)[0]
            y_pro_phishing = gbc.predict_proba(x)[0, 0]
            y_pro_non_phishing = gbc.predict_proba(x)[0, 1]
            pred = "It is {0:.2f} % safe to go ".format(y_pro_phishing * 100)
            return render_template('index.html', xx=round(y_pro_non_phishing, 2), url=input_data)

        elif mode == "pe":
            file_path = input_data
            # Change directory to the PE_Header directory
            os.chdir("./PE_Header")
            # Construct the command to run malware_test.py within this directory
            command = f"python malware_test.py {file_path}"
            try:
                result = subprocess.run(command, capture_output=True, text=True, shell=True, check=True)
                prediction_result = result.stdout.strip()
                # Determine if the file is safe based on the prediction
                if "legitimate" in prediction_result:
                    prediction_result = "The file is safe."
                print(f"PE file processing result: {prediction_result}")  # Debug print
            except subprocess.CalledProcessError as e:
                prediction_result = f"Error running malware_test.py: {e.stderr.strip()}"
                print(prediction_result)  # Debug print

            return render_template('index.html', prediction=prediction_result, mode="pe")

    return render_template("index.html", xx=-1)

if __name__ == "__main__":
    app.run(debug=True)

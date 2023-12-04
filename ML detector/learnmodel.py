import pandas as pd
import pickle
import pefile
import joblib
import numpy as np
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.feature_selection import SelectFromModel
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix

malaciousData = pd.read_csv("MalwareData.csv", sep="|")
legitimateFile = malaciousData[0:41323].drop(["legitimate"], axis=1)
malacious = malaciousData[41323::].drop(["legitimate"], axis=1)

print("The shape of the legit dataset is: %s samples, %s features" % (legitimateFile.shape[0], legitimateFile.shape[1]))
print("The shape of the malware dataset is: %s samples, %s features" % (malacious.shape[0], malacious.shape[1]))

print(malaciousData.columns)
print(malaciousData.head(5))
pd.set_option("display.max_columns", None)
print(malaciousData.head(5))

data_in = malaciousData.drop(['Name', 'md5', 'legitimate'], axis=1).values
labels = malaciousData['legitimate'].values

extratrees = ExtraTreesClassifier().fit(data_in, labels)
select = SelectFromModel(extratrees, prefit=True)
data_in_new = select.transform(data_in)

print(data_in.shape, data_in_new.shape)

features = data_in_new.shape[1]
importances = extratrees.feature_importances_
indices = np.argsort(importances)[::-1]
newfeatures = []

for f in range(features):
    print("%d" % (f + 1), malaciousData.columns[2 + indices[f]], importances[indices[f]])
    newfeatures.append(malaciousData.columns[2 + indices[f]])

# Save feature list to a file
np.savetxt('classifier/features.txt', newfeatures, fmt='%s')

legit_train, legit_test, mal_train, mal_test = train_test_split(data_in_new, labels, test_size=0.3)
classif = RandomForestClassifier(n_estimators=50)
algoclassifier = classif.fit(legit_train, mal_train)
print("The score of the algorithm:", classif.score(legit_test, mal_test) * 100)

print('Saving algorithm in classifier directory...')
joblib.dump(algoclassifier, 'classifier/classifier.pkl')

result = classif.predict(data_in_new)
conf_mat = confusion_matrix(labels, result)

print("False positives:", conf_mat[0][1] / sum(conf_mat[0]) * 100)
print("False negatives", conf_mat[1][0] / sum(conf_mat[1]) * 100)

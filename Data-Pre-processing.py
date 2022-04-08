# -*- coding: utf-8 -*-

# read dataset
import pandas as pd
traindata = pd.read_csv("Dataset\TrainingDay.csv")
# print(traindata.head())
# pd.set_option("display.max_rows", None)
# print(traindata['Total Fwd Packets'].value_counts(sort = 1))
# print(traindata['Subflow Fwd Packets'].dtype)


#%% delete columns that are clearly not relevant
traindata.drop(['Unnamed: 0', 'Flow ID', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Timestamp', 'SimillarHTTP', 'Inbound'], axis=1, inplace=True)

# delete columns with the same value or negative value
traindata.drop(['Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'FIN Flag Count', 'PSH Flag Count', 'ECE Flag Count', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Active Std', 'Idle Std', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'Fwd Header Length.1'], axis=1, inplace=True)


#%% handle non-numerical data
import numpy as np
traindata.loc[traindata['Label'] == 'BENIGN', 'Label'] = 0
traindata.loc[traindata['Label'] == 'DrDoS_DNS', 'Label'] = 1
traindata['Label'] = traindata['Label'].astype(int)
# delete rows with INF, NAN, negative values
traindata.replace([np.inf, -np.inf], np.nan, inplace=True)
traindata.dropna(inplace = True)
traindata = traindata[(traindata >= 0).all(axis=1)]


#%% define dependent variable Y
Y = traindata["Label"].values


#%% define independent variables X
X = traindata.drop(labels = ["Label"], axis=1)

# SPLIT THE DATA into TRAIN AND TEST data
# from sklearn.model_selection import train_test_split
# X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.2, random_state = 42)


#%% Feature selection
from sklearn.feature_selection import SelectKBest
from sklearn.feature_selection import f_classif
bestfeatures = SelectKBest(score_func = f_classif, k = 'all')
fit = bestfeatures.fit(X,Y)
tdscores = pd.DataFrame(fit.scores_)
tdcolumns = pd.DataFrame(X.columns)
featureScores = pd.concat([tdcolumns,tdscores],axis=1)
featureScores.columns = ['Columns','Score']  # naming the dataframe columns
print(featureScores.nlargest(10,'Score'))  # print 10 best features

X = X[['Fwd Packet Length Mean','Avg Fwd Segment Size','Min Packet Length','Fwd Packet Length Min','Packet Length Mean','Protocol','act_data_pkt_fwd','Average Packet Size','Total Fwd Packets','Subflow Fwd Packets']]


#%% random forest
from sklearn.ensemble import RandomForestClassifier
model = RandomForestClassifier(n_estimators = 20, random_state = 42)
model.fit(X, Y)


#%% Cross-validation
from sklearn.model_selection import cross_val_score
cv_scores = cross_val_score(model, X, Y, cv = 10)
print("\nCross-validation: %0.3f accuracy with a standard deviation of %0.3f\n" % (cv_scores.mean(), cv_scores.std()))


#%% assess the performance using TestingDay
testdata = pd.read_csv("Dataset\TestingDay.csv")
testdata = testdata[['Fwd Packet Length Mean','Avg Fwd Segment Size','Min Packet Length','Fwd Packet Length Min','Packet Length Mean','Protocol','act_data_pkt_fwd','Average Packet Size','Total Fwd Packets','Subflow Fwd Packets', 'Label']]
testdata.loc[testdata['Label'] == 'BENIGN', 'Label'] = 0
testdata.loc[testdata['Label'] == 'LDAP', 'Label'] = 1
testdata['Label'] = testdata['Label'].astype(int)
testdata.replace([np.inf, -np.inf], np.nan, inplace=True)
testdata.dropna(inplace = True)
testdata = testdata[(testdata >= 0).all(axis=1)]
X_Test = testdata[['Fwd Packet Length Mean','Avg Fwd Segment Size','Min Packet Length','Fwd Packet Length Min','Packet Length Mean','Protocol','act_data_pkt_fwd','Average Packet Size','Total Fwd Packets','Subflow Fwd Packets']]
Y_Test = testdata["Label"].values

predicted_labels = model.predict(X_Test)


#%% Confusion Matrix
from sklearn.metrics import confusion_matrix
from sklearn.metrics import ConfusionMatrixDisplay
cnf_matrix = confusion_matrix(Y_Test, predicted_labels)
cmd = ConfusionMatrixDisplay(cnf_matrix, display_labels=['Benign\n(Negative)', 'DDoS\n(Positive)'])
cmd.plot()


#%% Precision, Recall or F1
from sklearn.metrics import precision_score, recall_score, f1_score
print('Precision: %.3f' % precision_score(Y_Test, predicted_labels))
print('Recall: %.3f' % recall_score(Y_Test, predicted_labels))
print('F1 Score: %.3f' % f1_score(Y_Test, predicted_labels))


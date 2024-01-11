# coding=utf-8
import multiprocessing
import threading
from scapy.all import *
import ctypes
import tkinter.messagebox
from tkinter import ttk
import tkinter as tk
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import psutil


def onAnalyze():
    rt = pd.read_csv("traffic.pcap_Flow.csv")
    X_rt = rt[['Fwd Pkt Len Mean','Fwd Seg Size Avg','Pkt Len Min','Fwd Pkt Len Min','Pkt Len Mean','Protocol','Fwd Act Data Pkts','Pkt Size Avg','Tot Fwd Pkts','Subflow Fwd Pkts']] 

    X_rt.set_axis(['Fwd Packet Length Mean','Avg Fwd Segment Size','Min Packet Length','Fwd Packet Length Min','Packet Length Mean','Protocol','act_data_pkt_fwd','Average Packet Size','Total Fwd Packets','Subflow Fwd Packets'], axis='columns', inplace=True)

    X_rt.replace([np.inf, -np.inf], np.nan, inplace=True)
    X_rt.dropna(inplace = True)
    X_rt = X_rt[(X_rt >= 0).all(axis=1)]
    predicted_labels = model.predict(X_rt)
    attack = 0
    d_str = ''
    for i in range(len(predicted_labels)):
        if predicted_labels[i] == 1:
            found = 0
            for ii in range(len(connections)):
                if(connections[ii].laddr.ip == rt.iloc[i,1]):
                    if(connections[ii].laddr.port == rt.iloc[i,2]):
                        found = 1
                        break
                elif(connections[ii].laddr.ip == rt.iloc[i,3]):
                    if(connections[ii].laddr.port == rt.iloc[i,4]):
                        found = 1
                        break
            
            if (found == 0):
                continue
            
            nameofpro = ''
            for iii in range(len(processlist)):
                if(processlist[iii].pid == connections[ii].pid):
                    nameofpro = processlist[iii].name()
                    break

            if(nameofpro != '.exe'):
                attack = 1
                d_str = d_str + '\n' + nameofpro + '   ' + str(rt.iloc[i,1]) + ' : ' + str(rt.iloc[i,2]) + ' - ' + str(rt.iloc[i,3]) + ' : ' + str(rt.iloc[i,4])

    if attack == 0:
        tkinter.messagebox.showinfo(title='Detection', message='No attack has been found so far.')
    else:
        d_str = 'DDoS detected!\n' + d_str
        tkinter.messagebox.showinfo(title='Detection', message=d_str)


def trainingThread():
    df = pd.read_csv("Dataset\TrainingDay.csv")
    df = df[['Fwd Packet Length Mean','Avg Fwd Segment Size','Min Packet Length','Fwd Packet Length Min','Packet Length Mean','Protocol','act_data_pkt_fwd','Average Packet Size','Total Fwd Packets','Subflow Fwd Packets', 'Label']]
    df.loc[df['Label'] == 'BENIGN', 'Label'] = 0
    df.loc[df['Label'] == 'DrDoS_DNS', 'Label'] = 1
    df['Label'] = df['Label'].astype(int)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace = True)
    df = df[(df >= 0).all(axis=1)]
    Y = df["Label"].values
    X = df[['Fwd Packet Length Mean','Avg Fwd Segment Size','Min Packet Length','Fwd Packet Length Min','Packet Length Mean','Protocol','act_data_pkt_fwd','Average Packet Size','Total Fwd Packets','Subflow Fwd Packets']]

    global model
    model = RandomForestClassifier(n_estimators = 20, random_state = 42)
    model.fit(X, Y)

    #from sklearn import tree
    #from matplotlib import pyplot as plt        
    #for i in range(len(model.estimators_)):
        #fig = plt.figure(figsize=(50,50))
        #tree.plot_tree(model.estimators_[i], filled = True, feature_names = df.columns, class_names = ['Benign', 'DDoS'])
        #plt.savefig('.\\TheForest\\Tree#'+str(i), dpi = fig.dpi, bbox_inches = 'tight', pad_inches = 0.1)
        #plt.show()            
        #plt.close()
    
    label.configure(text = "Done        ")
    Button_0["state"] = "normal"


def onTraining():
    Button_0["state"] = "disabled"
    label.configure(text = 'Training...')
    startThread(trainingThread)


def handelPacket(p):
    # p.show()
    addTreeData = []
    addTreeData.append(p[IP].src)
    addTreeData.append(p[IP].dst)
    if p[IP].proto == 6:
        addTreeData.append('TCP')
        addTreeData.append(p[TCP].sport)
        addTreeData.append(p[TCP].dport)

    elif p[IP].proto == 17:
        addTreeData.append('UDP')
        addTreeData.append(p[UDP].sport)
        addTreeData.append(p[UDP].dport)

    index = treeview.insert('', 'end', values=addTreeData)
    treeview.see(index)
    root.update()
    wrpcap('traffic.pcap', p, append=True)



def getPack():
    sniff(filter="(tcp or udp) and ip and !multicast", count=0, prn=handelPacket)
    


def startThread(func, *args):
    global t
    t = threading.Thread(target=func)
    t.setDaemon(True)
    t.start()


def _async_raise(tid, exctype):
    # """raises the exception, performs cleanup if needed"""
    tid = ctypes.c_long(tid)
    if not inspect.isclass(exctype):
        exctype = type(exctype)
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, ctypes.py_object(exctype))
    if res == 0:
        raise ValueError("invalid thread id")
    elif res != 1:
        # """if it returns a number greater than one, you're in trouble,
        # and you should call it again with exc=NULL to revert the effect"""
        ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, None)
        raise SystemError("PyThreadState_SetAsyncExc failed")


def stopThread():
    _async_raise(t.ident, SystemExit)


b1_state = 0
def onStart():
    global b1_state
    if (b1_state % 2) == 0:
        startThread(getPack)
        Button_1['text'] = 'Stop'

    else:
        stopThread()
        global processlist
        processlist = []
        for proc in psutil.process_iter():
            processlist.append(psutil.Process(proc.pid))
        global connections
        connections = psutil.net_connections(kind="inet4")
        Button_1['text'] = 'Start'    

    b1_state += 1


def about():
    info_string = 'DDoS Detection V1.0 '
    tkinter.messagebox.showinfo(title='About', message=info_string)


if __name__ == '__main__':

    multiprocessing.freeze_support()
    root = tk.Tk()
    root.resizable(False, False)
    root.title("DDoS Detection")
    root.geometry('780x720')

    ctypes.windll.shcore.SetProcessDpiAwareness(1)
    ScaleFactor = ctypes.windll.shcore.GetScaleFactorForDevice(0)
    root.tk.call('tk', 'scaling', ScaleFactor / 75)

    Button_0 = tk.Button(root, text='Training', width=10, height=1, command=onTraining)
    Button_0.grid(row=0, column=0, padx=10, pady=10)
    
    Button_1 = tk.Button(root, text='Start', width=10, height=1, command=onStart)
    Button_1.grid(row=0, column=1, padx=10, pady=10)

    Button_2 = tk.Button(root, text='Analyze', width=10, height=1, command=onAnalyze)
    Button_2.grid(row=0, column=2, padx=10, pady=10)
    
    Button_3 = tk.Button(root, text='About', width=10, height=1, command=about)
    Button_3.grid(row=0, column=3, padx=10, pady=10)

    treeview = ttk.Treeview(root, height=30)
    treeview['show'] = 'headings'
    treeview['column'] = ('Source IP', 'Destination IP', 'Protocol', 'SPort', 'DPort')
    for column in treeview['column']:
        treeview.column(column, width=150)
        treeview.heading(column, text=column)

    treeview.grid(row=1, column=0, columnspan=6, sticky='NSEW')

    vbar = ttk.Scrollbar(root, orient='vertical', command=treeview.yview)
    treeview.configure(yscrollcommand=vbar.set)
    vbar.grid(row=1, column=7, sticky='NS')

    label = tk.Label(root, text = "            ")
    label.grid(row=2, column=0, sticky='NW')

    root.mainloop()

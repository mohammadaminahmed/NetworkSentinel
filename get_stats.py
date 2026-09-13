import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.preprocessing import LabelEncoder
import xgboost as xgb
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from scipy import stats
import hashlib
import json

def main():
    np.random.seed(42)
    n_samples = 3000
    device_type = np.random.choice(['Cloud', 'Edge', 'IoT', 'Mobile'], n_samples)
    security_level = np.random.choice([1, 3, 5], n_samples)
    cpu_speed = np.random.randint(50, 4000, n_samples)
    network_rtt = np.random.randint(10, 300, n_samples)
    power_budget = np.random.randint(10, 500, n_samples)
    payload_size = np.random.randint(1000, 5000000, n_samples)
    cpu_load = np.random.randint(1, 100, n_samples)
    available_memory = np.random.randint(50, 16000, n_samples)
    
    le_device = LabelEncoder()
    device_encoded = le_device.fit_transform(device_type)
    
    def select_algorithm(device, sec, cpu, rtt, power, payload, load, mem):
        if device == 2: # IoT
            if power < 100 or mem < 500: return 0
            elif sec <= 3: return 1
            else: return 2
        elif device == 0: # Cloud
            if sec == 5 or cpu > 2000: return 2
            else: return 1
        else:
            if sec <= 3 and power > 100: return 1
            else: return 0
            
    y = np.array([select_algorithm(d, s, c, r, p, pl, l, m) 
                  for d, s, c, r, p, pl, l, m in zip(
                      device_encoded, security_level, cpu_speed, network_rtt, 
                      power_budget, payload_size, cpu_load, available_memory)])
    X = np.column_stack([device_encoded, security_level, cpu_speed, network_rtt,
                         power_budget, payload_size, cpu_load, available_memory])
    
    df = pd.DataFrame(X)
    df['y'] = y
    df.to_csv('temp.csv', index=False)
    checksum = hashlib.sha256(open('temp.csv', 'rb').read()).hexdigest()
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.15, random_state=42, stratify=y)
    
    xgb_model = xgb.XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, random_state=42)
    rf_model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, class_weight='balanced')
    xgb_model.fit(X_train, y_train)
    rf_model.fit(X_train, y_train)
    
    xgb_p = xgb_model.predict_proba(X_test)
    rf_p = rf_model.predict_proba(X_test)
    ens_p = (xgb_p + rf_p) / 2
    
    metrics = {}
    for name, p in zip(['XGB', 'RF', 'Ens'], [xgb_p, rf_p, ens_p]):
        pred = np.argmax(p, axis=1)
        metrics[name] = {
            'Acc': accuracy_score(y_test, pred),
            'F1': f1_score(y_test, pred, average='weighted'),
            'Prec': precision_score(y_test, pred, average='weighted'),
            'Rec': recall_score(y_test, pred, average='weighted')
        }
        
    skf = StratifiedKFold(n_splits=10, shuffle=True, random_state=42)
    x_acc, r_acc, e_acc = [], [], []
    for tr, ts in skf.split(X, y):
        xtr, xts = X[tr], X[ts]
        ytr, yts = y[tr], y[ts]
        xm = xgb.XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, random_state=42).fit(xtr, ytr)
        rm = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, class_weight='balanced').fit(xtr, ytr)
        xp = xm.predict_proba(xts)
        rp = rm.predict_proba(xts)
        ep = (xp + rp) / 2
        x_acc.append(accuracy_score(yts, np.argmax(xp, axis=1)))
        r_acc.append(accuracy_score(yts, np.argmax(rp, axis=1)))
        e_acc.append(accuracy_score(yts, np.argmax(ep, axis=1)))
        
    def stats_test(acc1, acc2):
        acc1, acc2 = np.array(acc1), np.array(acc2)
        diff = acc1 - acc2
        t, p = stats.ttest_rel(acc1, acc2)
        md = np.mean(diff)
        sd = np.std(diff, ddof=1)
        ci_l = md - stats.t.ppf(0.975, 9) * (sd / np.sqrt(10))
        ci_u = md + stats.t.ppf(0.975, 9) * (sd / np.sqrt(10))
        d = md / sd if sd > 0 else 0
        return {'t': t, 'p': p, 'ci_l': ci_l, 'ci_u': ci_u, 'd': d, 'md': md, 'sd': sd}
        
    res = {
        'checksum': checksum,
        'metrics': metrics,
        'stats_xgb': stats_test(e_acc, x_acc),
        'stats_rf': stats_test(e_acc, r_acc),
        'means': {'Ens': np.mean(e_acc), 'XGB': np.mean(x_acc), 'RF': np.mean(r_acc)},
        'sds': {'Ens': np.std(e_acc, ddof=1), 'XGB': np.std(x_acc, ddof=1), 'RF': np.std(r_acc, ddof=1)}
    }
    print(json.dumps(res, indent=2))

if __name__ == '__main__':
    main()

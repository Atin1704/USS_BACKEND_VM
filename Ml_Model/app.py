from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from tld import get_tld
from urllib.parse import urlparse
import pandas as pd
import numpy as np
import onnxruntime as ort
import uvicorn
import re
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.utils import class_weight, resample
from scipy import sparse
import joblib
import json

# def process_tld(url):
#     try:
#         res = get_tld(url, as_object = True, fail_silently=False,fix_protocol=True)
#         pri_domain= res.parsed_url.netloc
#     except :
#         pri_domain= None
#     return pri_domain

# def abnormal_url(url):
#     hostname = urlparse(url).hostname
#     hostname = str(hostname)
#     match = re.search(hostname, url)
#     if match:
#         return 1
#     else:
#         return 0
    
# def httpSecure(url):
#     htp = urlparse(url).scheme
#     match = str(htp)
#     if match=='https':
#         return 1
#     else:
#         return 0
    
# def digit_count(url):
#     digits = 0
#     for i in url:
#         if i.isnumeric():
#             digits = digits + 1
#     return digits

# def letter_count(url):
#     letters = 0
#     for i in url:
#         if i.isalpha():
#             letters = letters + 1
#     return letters

# def Shortining_Service(url):
#     match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
#                       'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
#                       'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
#                       'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
#                       'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
#                       'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
#                       'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
#                       'tr\.im|link\.zip\.net',
#                       url)
#     if match:
#         return 1
#     else:
#         return 0
    
# def having_ip_address(url):
#     match = re.search(
#         '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
#         '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
#         '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
#         '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4 with port
#         '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
#         '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
#         '([0-9]+(?:\.[0-9]+){3}:[0-9]+)|'
#         '((?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?)', url)  # Ipv6
#     if match:
#         return 1
#     else:
#         return 0

# def deprecated_feature_extraction(data : pd.DataFrame):
#     data.isnull().sum()
#     data['url'] = data['url'].replace('www.', '', regex=True)
#     rem = {"Category": {"benign": 0, "defacement": 1, "phishing":2, "malware":3}}
#     data['Category'] = data['type']
#     data = data.replace(rem)
#     data['url_len'] = data['url'].apply(lambda x: len(str(x)))
#     data['domain'] = data['url'].apply(lambda i: process_tld(i))
#     feature = ['@','?','-','=','.','#','%','+','$','!','*',',','//']
#     for a in feature:
#         data[a] = data['url'].apply(lambda i: i.count(a))
#     data['abnormal_url'] = data['url'].apply(lambda i: abnormal_url(i))
#     data['https'] = data['url'].apply(lambda i: httpSecure(i))
#     data['digits']= data['url'].apply(lambda i: digit_count(i))
#     data['letters']= data['url'].apply(lambda i: letter_count(i))
#     data['Shortining_Service'] = data['url'].apply(lambda x: Shortining_Service(x))
#     data['having_ip_address'] = data['url'].apply(lambda i: having_ip_address(i))

# def feature_extraction(data : pd.DataFrame):
#     if 'text' in data.columns and 'url' not in data.columns:
#         data = data.rename(columns={'text':'url'})
#     if 'label' in data.columns and 'type' not in data.columns:
#         data = data.rename(columns={'label':'type'})

#     if 'source' not in data.columns:
#         data = data.reset_index(drop=True)
#         data['source'] = 'merged'

#     data.drop_duplicates(subset=['url', 'type'], inplace=True)

#     def clean_url(u):
#         if pd.isna(u): 
#             return ''
#         u = str(u).strip().lower()
#         u = re.sub(r'^https?://', '', u)
#         u = re.sub(r'^www\.', '', u)
#         u = u.rstrip('/')
#         return u

#     data['url'] = data['url'].astype(str).apply(clean_url)

#     vectorizer = HashingVectorizer(analyzer='char_wb', ngram_range=(3,5), n_features=50000, alternate_sign=False)
#     X = vectorizer.fit_transform(data['url'])

#     joblib.dump(vectorizer, "tfidf_vectorizer_merged.joblib")

#     le = LabelEncoder()
#     y = le.fit_transform(data['type'].astype(str))

#     X_train, X_test, y_train, y_test, idx_train, idx_test = train_test_split(
#         X, y, data.index, test_size=0.2, random_state=42, stratify=y
#     )

#     cw = class_weight.compute_class_weight('balanced', classes=np.unique(y_train), y=y_train)
#     class_weights = {i: float(w) for i, w in enumerate(cw)}

#     globals().update({
#         'vectorizer_merged': vectorizer,
#         'X': X, 'X_train': X_train, 'X_test': X_test,
#         'y': y, 'y_train': y_train, 'y_test': y_test,
#         'idx_train': idx_train, 'idx_test': idx_test,
#         'label_encoder': le, 'class_weights': class_weights
#     })

#     y = np.where(np.array(y) > 0, 1, 0)
#     y_train = np.where(np.array(y_train) > 0, 1, 0)
#     y_test  = np.where(np.array(y_test) > 0, 1, 0)

#     DO_RESAMPLE = True

#     if DO_RESAMPLE:
#         # Build a dataframe for resampling using training indices
#         train_df = data.loc[idx_train].copy()
#         train_df["y"] = y_train

#         df_major = train_df[train_df["y"] == 0]
#         df_minor = train_df[train_df["y"] == 1]

#         df_minor_upsampled = resample(
#             df_minor,
#             replace=True,
#             n_samples=len(df_major),
#             random_state=42
#         )

#         train_df_resampled = (
#             pd.concat([df_major, df_minor_upsampled])
#             .sample(frac=1, random_state=42)
#             .reset_index(drop=True)
#         )

#         # Recreate resampled feature matrix and labels
#         X_train_resampled = vectorizer_merged.transform(train_df_resampled["url"])
#         y_train_resampled = train_df_resampled["y"].values

#         globals().update({
#             "X_train_resampled": X_train_resampled,
#             "y_train_resampled": y_train_resampled,
#             "y_train": y_train,
#             "y_test": y_test,
#             "y": y
#         })

#     ip_pattern = re.compile(
#         r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.'    # IPv4 octet
#         r'([01]?\d\d?|2[0-4]\d|25[0-5])\.'
#         r'([01]?\d\d?|2[0-4]\d|25[0-5])\.'
#         r'([01]?\d\d?|2[0-4]\d|25[0-5])\/)|'
#         r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.'    # alternate IPv4 variants
#         r'([01]?\d\d?|2[0-4]\d|25[0-5])\.'
#         r'([01]?\d\d?|2[0-4]\d|25[0-5])\.'
#         r'([01]?\d\d?|2[0-4]\d|25[0-5])\/)|'
#         r'((0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\/)|'
#         r'(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}|'  # IPv6 basic
#         r'([0-9]+(?:\.[0-9]+){3}:[0-9]+)|'
#         r'((?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}'
#         r'(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?)'
#     )
#     def having_ip_address(u: str) -> bool:
#         if u is None:
#             return False
#         return bool(ip_pattern.search(u))

#     def safe_urlparse(u):
#         """Robust urlparse: avoids ValueError from malformed IPv6 and handles IP hosts."""
#         if u is None:
#             return None
#         s = str(u).strip()
#         if not s:
#             return None

#         # normalize by removing scheme and leading '//' if present
#         s_noproto = re.sub(r'^[a-zA-Z]+://', '', s)
#         s_noproto = re.sub(r'^//', '', s_noproto)

#         # If host looks like an IP, build a minimal parse-like object to avoid urlparse errors
#         if having_ip_address(s_noproto):
#             host = s_noproto.split('/')[0].split('?')[0].strip()
#             host = host.split('@')[-1].split(':')[0]  # remove creds/port if any
#             class FakeParse:
#                 def __init__(self, netloc, path, query=''):
#                     self.netloc = netloc
#                     self.path = path
#                     self.query = query
#             return FakeParse(host, '')

#         # Normal parsing with safe fallbacks
#         try:
#             return urlparse('http://' + s_noproto)
#         except ValueError:
#             # try stripping unmatched brackets (common IPv6 scrape issue)
#             s_fixed = s_noproto.replace('[', '').replace(']', '')
#             try:
#                 return urlparse('http://' + s_fixed)
#             except Exception:
#                 # last-resort: extract host-like prefix
#                 host = s_noproto.split('/')[0].split('?')[0].strip()
#                 if not host:
#                     return None
#                 host = host.split('@')[-1].split(':')[0]
#                 class FakeParse2:
#                     def __init__(self, netloc, path, query=''):
#                         self.netloc = netloc
#                         self.path = path
#                         self.query = query
#                 return FakeParse2(host, '')

#     def extract_url_features(u):
#         parsed = safe_urlparse(u)
#         s = '' if u is None else str(u)
#         if parsed is None:
#             # fallback defaults for totally unparseable strings
#             return {
#                 'domain_len': 0,
#                 'path_len': 0,
#                 'num_dots': s.count('.'),
#                 'num_digits': sum(c.isdigit() for c in s),
#                 'num_special': sum(1 for c in s if not c.isalnum() and c not in ['.', '/', ':', '-','_']),
#                 'has_at': int('@' in s),
#                 'has_dash': int('-' in s),
#                 'has_ip': int(having_ip_address(s)),
#                 'tld': ''
#             }

#         # safe extraction: remove credentials & port
#         domain = parsed.netloc.split('@')[-1].split(':')[0] if parsed.netloc else ''
#         path = parsed.path or ''
#         tld = domain.split('.')[-1] if domain and '.' in domain else ''
#         return {
#             'domain_len': len(domain),
#             'path_len': len(path),
#             'num_dots': domain.count('.') + path.count('.'),
#             'num_digits': sum(c.isdigit() for c in s),
#             'num_special': sum(1 for c in s if not c.isalnum() and c not in ['.', '/', ':', '-','_']),
#             'has_at': int('@' in s),
#             'has_dash': int('-' in s),
#             'has_ip': int(having_ip_address(s)),
#             'tld': tld
#         }

#     # Apply feature extraction
#     vals = data['url'].astype(str).values
#     feat_dicts = [extract_url_features(u) for u in vals]
#     feat_df = pd.DataFrame(feat_dicts, index=data.index)

#     # Ensure boolean/int columns are ints
#     for c in ['has_at', 'has_dash', 'has_ip']:
#         if c in feat_df.columns:
#             feat_df[c] = feat_df[c].astype(int)

#     # One-hot encode top-k TLDs and leave others as 'other'
#     top_tlds = feat_df['tld'].value_counts().nlargest(20).index.tolist()
#     feat_df['tld'] = feat_df['tld'].apply(lambda x: x if x in top_tlds else 'other')
#     feat_df = pd.get_dummies(feat_df, columns=['tld'], prefix='tld')

#     # Standardize numeric features and create sparse matrix
#     num_cols = ['domain_len','path_len','num_dots','num_digits','num_special','has_at','has_dash','has_ip']
#     scaler = StandardScaler(with_mean=False)  # with_mean=False to allow sparse hstack later
#     feat_num = scaler.fit_transform(feat_df[num_cols])

#     # Create sparse matrix for non-numeric (one-hot) columns
#     feat_others = sparse.csr_matrix(feat_df.drop(columns=num_cols).values)

#     # Combine numeric and other features into a sparse matrix
#     url_struct_feats = sparse.hstack([feat_num, feat_others], format='csr')

#     # Combine TF-IDF / Hashing matrix X with URL structural features
#     X_with_struct = sparse.hstack([X, url_struct_feats], format='csr')

#     # Expose variables for downstream cells
#     globals().update({'feat_df': feat_df, 'X_with_struct': X_with_struct})

def feature_extraction_test(data, vectorizer, scaler, top_tlds):
    """
    Test-time URL feature extraction matching training-time processing.
    Requires:
        - vectorizer: HashingVectorizer (loaded)
        - scaler: StandardScaler(with_mean=False) (loaded)
        - top_tlds: list of top TLDs from training (loaded)
    """

    # -------------------------------
    # 1. Normalize input columns
    # -------------------------------
    if "text" in data.columns and "url" not in data.columns:
        data = data.rename(columns={"text": "url"})

    if "url" not in data.columns:
        raise ValueError("Data must contain a 'url' or 'text' column.")

    data = data.copy()
    data.drop_duplicates(subset=["url"], inplace=True)
    data.reset_index(drop=True, inplace=True)

    # -------------------------------
    # 2. URL Cleaner (same as training)
    # -------------------------------
    def clean_url(u):
        if pd.isna(u):
            return ""
        u = str(u).strip().lower()
        u = re.sub(r"^https?://", "", u)
        u = re.sub(r"^www\.", "", u)
        u = u.rstrip("/")
        return u

    data["url"] = data["url"].astype(str).apply(clean_url)

    # -------------------------------
    # 3. Regex for IP detection
    # -------------------------------
    ip_pattern = re.compile(
        r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}'
        r'([01]?\d\d?|2[0-4]\d|25[0-5])'
    )

    def having_ip_address(u):
        if u is None:
            return False
        return bool(ip_pattern.search(u))

    # -------------------------------
    # 4. Safe parsing
    # -------------------------------
    def safe_urlparse(u):
        if u is None:
            return None
        s = str(u).strip()
        if not s:
            return None

        s_noproto = re.sub(r"^[a-zA-Z]+://", "", s)
        s_noproto = re.sub(r"^//", "", s_noproto)

        if having_ip_address(s_noproto):
            host = s_noproto.split("/")[0].split("?")[0].strip()
            class FP:
                def __init__(self, netloc, path):
                    self.netloc = netloc
                    self.path = path
            return FP(host, "")

        try:
            return urlparse("http://" + s_noproto)
        except:
            s_fixed = s_noproto.replace("[", "").replace("]", "")
            try:
                return urlparse("http://" + s_fixed)
            except:
                host = s_noproto.split("/")[0].split("?")[0].strip()
                class FP2:
                    def __init__(self, netloc, path):
                        self.netloc = netloc
                        self.path = path
                return FP2(host, "")

    # -------------------------------
    # 5. Extract structural features
    # -------------------------------
    def extract_url_features(u):
        parsed = safe_urlparse(u)
        s = str(u)

        if parsed is None:
            domain = ""
            path = ""
        else:
            domain = parsed.netloc.split("@")[-1].split(":")[0] if parsed.netloc else ""
            path = parsed.path or ""

        tld = domain.split(".")[-1] if ("." in domain) else ""

        return {
            "domain_len": len(domain),
            "path_len": len(path),
            "num_dots": domain.count(".") + path.count("."),
            "num_digits": sum(c.isdigit() for c in s),
            "num_special": sum(1 for c in s if not c.isalnum() and c not in ['.', '/', ':', '-', '_']),
            "has_at": int("@" in s),
            "has_dash": int("-" in s),
            "has_ip": int(having_ip_address(s)),
            "tld": tld
        }

    feat_df = pd.DataFrame([extract_url_features(u) for u in data["url"]])

    # -------------------------------
    # 6. Apply training top-20 TLD mapping
    # -------------------------------
    feat_df["tld"] = feat_df["tld"].apply(lambda x: x if x in top_tlds else "other")

    # Create OHE columns in training-time exact order
    for t in top_tlds + ["other"]:
        feat_df[f"tld_{t}"] = (feat_df["tld"] == t).astype(int)

    feat_df.drop(columns=["tld"], inplace=True)

    # -------------------------------
    # 7. Numeric feature scaling
    # -------------------------------
    num_cols = ["domain_len","path_len","num_dots","num_digits",
                "num_special","has_at","has_dash","has_ip"]

    numeric_scaled = scaler.transform(feat_df[num_cols])

    # OHE sparse
    ohe_cols = [c for c in feat_df.columns if c not in num_cols]
    ohe_sparse = sparse.csr_matrix(feat_df[ohe_cols].values)

    struct_sparse = sparse.hstack([numeric_scaled, ohe_sparse], format="csr")

    # -------------------------------
    # 8. HashingVectorizer transform
    # -------------------------------
    X_hash = vectorizer.transform(data["url"])

    # -------------------------------
    # 9. Final matrix
    # -------------------------------
    X_final = sparse.hstack([X_hash, struct_sparse], format="csr")

    return X_final, data

def sigmoid(x):
    return 1 / (1 + np.exp(-x))

# ----- FastAPI Setup -----
app = FastAPI(
    title="ML Prediction API",
    description="Serve predictions from an ONNX model",
    version="1.0.0"
)

# ----- Load Model Once -----
session = ort.InferenceSession("model.onnx", providers=["CPUExecutionProvider"])
input_name = session.get_inputs()[0].name
output_name = session.get_outputs()[0].name

# ----- Input Schema -----
class Features(BaseModel):
    features: list

# ----- Predict Endpoint -----
@app.post("/predict")
async def predict(data: Features):
    try:

        vectorizer = joblib.load("vectorizer_merged.joblib")
        scaler = joblib.load("scaler.joblib")

        with open("top_tlds.json") as f:
            top_tlds = json.load(f)
        rawX = pd.DataFrame({"url":data.features})
        X_test, df_processed = feature_extraction_test(rawX, vectorizer, scaler, top_tlds)
        X_test = X_test.toarray().astype(np.float32)

        outputs = session.run(None, {input_name: X_test})
        labels = outputs[0]
        margins = outputs[1]

        def temperature_scaled_sigmoid(x, t=0.25):
            return 1 / (1 + np.exp(-x / t))

        unsafe_probs = temperature_scaled_sigmoid(margins)

        def risk_level(p):
            if p < 0.10: return "very_safe"
            if p < 0.33: return "low_risk"
            if p < 0.66: return "medium_risk"
            if p < 0.90: return "high_risk"
            return "very_high_risk"

        results = []
        for url, p, l in zip(data.features, unsafe_probs, labels):
            results.append({
                "url": url,
                "label": int(l),
                "probability_unsafe": float(p[1]),
                "risk_level": risk_level(p[1])
            })

        return {"prediction": results}

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# ----- Health Check -----
@app.get("/health")
def health():
    return {"status": "ok"}

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000)

# uvicorn app:app --host 0.0.0.0 --port 8000 --workers 2
import json
import joblib
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Dict, Any, List, Optional


class TrafficPredictor:
    """
    Single source of truth for inference.

    Responsibilities:
    - Load preprocessing artifacts and trained model
    - Normalize incoming traffic dataframe
    - Keep only trained features in exact order
    - Encode categorical columns safely
    - Apply scaler if required
    - Predict normal / attack
    - Return prediction metadata for logs, dashboard, and alerts
    """

    def __init__(self, base_dir: str):
        self.base_dir = Path(base_dir).resolve()
        self.models_dir = self.base_dir / "models"

        config_path = self.models_dir / "preprocessing_config.json"
        encoders_path = self.models_dir / "label_encoders.pkl"

        if not config_path.exists():
            raise FileNotFoundError(f"Missing preprocessing config: {config_path}")
        if not encoders_path.exists():
            raise FileNotFoundError(f"Missing encoders file: {encoders_path}")

        with open(config_path, "r", encoding="utf-8") as f:
            self.config = json.load(f)

        self.encoders = joblib.load(encoders_path)

        self.feature_order: List[str] = self.config.get("final_feature_order", [])
        self.categorical_columns: List[str] = self.config.get("categorical_columns", [])
        self.numeric_columns: List[str] = self.config.get("numeric_columns", [])

        if not self.feature_order:
            raise ValueError("preprocessing_config.json missing 'final_feature_order'")

        self.loaded_models: Dict[str, Dict[str, Any]] = {}

        # Keep useful fields for alert display if present in original input
        self.preserve_columns = [
            "ip_src", "ip_dst", "src_ip", "dst_ip", "source", "destination",
            "source_ip", "destination_ip", "protocol", "frame_time", "time", "info"
        ]

    def _resolve_artifact_path(self, path_str: str) -> Path:
        """
        Resolve artifact path from config.
        Supports both absolute and relative paths.
        Relative paths are resolved against base_dir.
        """
        p = Path(path_str)
        if p.is_absolute():
            return p
        return (self.base_dir / p).resolve()

    def load_model(self, model_name: str):
        if model_name in self.loaded_models:
            return self.loaded_models[model_name]

        model_cfg = self.config.get("model_artifacts", {}).get(model_name)
        if not model_cfg:
            raise ValueError(f"Unknown model name: {model_name}")

        model_path = self._resolve_artifact_path(model_cfg["model_path"])
        if not model_path.exists():
            raise FileNotFoundError(f"Model file not found: {model_path}")

        model = joblib.load(model_path)

        scaler = None
        if model_cfg.get("scaler_required", False):
            scaler_path_str = model_cfg.get("scaler_path")
            if not scaler_path_str:
                raise ValueError(f"Scaler required but scaler_path missing for model: {model_name}")

            scaler_path = self._resolve_artifact_path(scaler_path_str)
            if not scaler_path.exists():
                raise FileNotFoundError(f"Scaler file not found: {scaler_path}")

            scaler = joblib.load(scaler_path)

        self.loaded_models[model_name] = {
            "model": model,
            "scaler": scaler,
            "config": model_cfg
        }
        return self.loaded_models[model_name]

    def _normalize_column_name(self, col: str) -> str:
        clean = str(col).strip().lower()
        for ch in [" ", ".", "/", "-", ":", "(", ")", "[", "]"]:
            clean = clean.replace(ch, "_")
        while "__" in clean:
            clean = clean.replace("__", "_")
        return clean.strip("_")

    def _safe_label_encode(self, series: pd.Series, column_name: str) -> pd.Series:
        """
        Encode categorical values safely.
        Unknown/unseen values -> -1
        """
        encoder = self.encoders.get(column_name)
        if encoder is None:
            return pd.Series([-1] * len(series), index=series.index)

        known_classes = set(map(str, encoder.classes_))
        values = series.fillna("unknown").astype(str)

        encoded = []
        for val in values:
            if val in known_classes:
                encoded.append(int(encoder.transform([val])[0]))
            else:
                encoded.append(-1)

        return pd.Series(encoded, index=series.index)

    def _rename_and_standardize_columns(self, df: pd.DataFrame) -> pd.DataFrame:
        work_df = df.copy()

        # Normalize all incoming column names
        rename_map = {col: self._normalize_column_name(col) for col in work_df.columns}
        work_df = work_df.rename(columns=rename_map)

        # Standard aliases from Wireshark/CSV exports
        alias_map = {
            "src_port": "source_port",
            "source_port": "source_port",
            "tcp_srcport": "source_port",

            "dst_port": "dst_port",
            "destination_port": "dst_port",
            "tcp_dstport": "dst_port",

            "ip_proto": "protocol",
            "_ws_col_protocol": "protocol",
            "protocol": "protocol",

            "frame_len": "length",
            "packet_length": "length",
            "length": "length",

            "time_delta": "delta_time",
            "delta_time": "delta_time",
            "frame_time_delta": "delta_time",

            "ip_src": "ip_src",
            "src_ip": "ip_src",
            "source_ip": "ip_src",

            "ip_dst": "ip_dst",
            "dst_ip": "ip_dst",
            "destination_ip": "ip_dst",

            "_ws_col_info": "info",
            "info": "info",
        }

        work_df = work_df.rename(columns=alias_map)

        # Remove duplicated columns after rename
        work_df = work_df.loc[:, ~work_df.columns.duplicated()]

        return work_df

    def preprocess_dataframe(
        self,
        df: pd.DataFrame,
        return_metadata: bool = False
    ):
        if df is None or df.empty:
            raise ValueError("Input dataframe is empty.")

        original_df = df.copy()
        work_df = self._rename_and_standardize_columns(df)

        metadata = {
            "original_columns": list(original_df.columns),
            "normalized_columns": list(work_df.columns),
            "missing_features_added": [],
            "extra_columns_dropped": [],
            "categorical_columns_encoded": [],
            "numeric_columns_cleaned": [],
            "rows_processed": len(work_df)
        }

        # Preserve useful raw fields from original standardized input for alerting
        preserved_df = pd.DataFrame(index=work_df.index)
        for col in self.preserve_columns:
            if col in work_df.columns:
                preserved_df[col] = work_df[col]

        # Detect extra columns before filtering
        current_columns = set(work_df.columns)
        expected_columns = set(self.feature_order)
        metadata["extra_columns_dropped"] = sorted(list(current_columns - expected_columns))

        # Ensure all expected features exist
        for col in self.feature_order:
            if col not in work_df.columns:
                if col in self.categorical_columns:
                    work_df[col] = "unknown"
                else:
                    work_df[col] = 0
                metadata["missing_features_added"].append(col)

        # Keep only training schema
        work_df = work_df[self.feature_order].copy()

        # Clean categorical columns
        for col in self.categorical_columns:
            work_df[col] = work_df[col].fillna("unknown").astype(str)
            work_df[col] = self._safe_label_encode(work_df[col], col)
            metadata["categorical_columns_encoded"].append(col)

        # Clean numeric columns
        for col in self.numeric_columns:
            if col in work_df.columns:
                work_df[col] = pd.to_numeric(work_df[col], errors="coerce")
                work_df[col] = work_df[col].replace([np.inf, -np.inf], np.nan).fillna(0)
                metadata["numeric_columns_cleaned"].append(col)

        # Final safety
        work_df = work_df.replace([np.inf, -np.inf], 0).fillna(0)

        if return_metadata:
            return work_df, metadata, preserved_df
        return work_df

    def predict(
        self,
        df: pd.DataFrame,
        model_name: str = "random_forest"
    ) -> pd.DataFrame:
        """
        Predict traffic class using selected model.

        Supported model names:
        - random_forest
        - svm
        - isolation_forest
        """
        loaded = self.load_model(model_name)
        model = loaded["model"]
        scaler = loaded["scaler"]

        X, metadata, preserved_df = self.preprocess_dataframe(df, return_metadata=True)

        X_input = X.copy()
        if scaler is not None:
            X_input = scaler.transform(X_input)

        # Prediction
        if model_name == "isolation_forest":
            raw_pred = model.predict(X_input)
            pred = np.where(raw_pred == -1, 1, 0)
            confidence = [None] * len(pred)
        else:
            pred = model.predict(X_input)

            if hasattr(model, "predict_proba"):
                proba = model.predict_proba(X_input)
                # attack probability = class 1 if present
                if proba.shape[1] > 1:
                    confidence = proba[:, 1]
                else:
                    confidence = proba[:, 0]
            elif hasattr(model, "decision_function"):
                scores = model.decision_function(X_input)
                scores = np.array(scores).reshape(-1)
                # normalize approximately to 0-1
                min_s, max_s = scores.min(), scores.max()
                if max_s > min_s:
                    confidence = (scores - min_s) / (max_s - min_s)
                else:
                    confidence = np.zeros_like(scores, dtype=float)
            else:
                confidence = [None] * len(pred)

        result_df = pd.DataFrame(index=df.index)

        # Preserve helpful original columns if available
        for col in preserved_df.columns:
            result_df[col] = preserved_df[col]

        result_df["prediction"] = pred
        result_df["prediction_label"] = result_df["prediction"].map({
            0: "normal",
            1: "attack"
        })

        if confidence is not None:
            result_df["confidence"] = confidence

        result_df["model_used"] = model_name
        result_df["rows_processed"] = metadata["rows_processed"]
        result_df["missing_features_added"] = ", ".join(metadata["missing_features_added"])
        result_df["extra_columns_dropped"] = ", ".join(metadata["extra_columns_dropped"])

        return result_df

    def predict_csv(
        self,
        csv_path: str,
        model_name: str = "random_forest"
    ) -> pd.DataFrame:
        csv_path = Path(csv_path)
        if not csv_path.exists():
            raise FileNotFoundError(f"CSV file not found: {csv_path}")

        # Robust CSV loading for mixed encodings
        read_attempts = [
            {"encoding": "utf-8"},
            {"encoding": "latin1"},
            {"encoding": "cp1252"},
        ]

        last_error = None
        df = None
        for kwargs in read_attempts:
            try:
                df = pd.read_csv(csv_path, **kwargs)
                break
            except Exception as e:
                last_error = e

        if df is None:
            raise ValueError(f"Failed to read CSV file: {csv_path}. Last error: {last_error}")

        return self.predict(df, model_name=model_name)

    def get_expected_features(self) -> List[str]:
        return self.feature_order

    def get_supported_models(self) -> List[str]:
        return list(self.config.get("model_artifacts", {}).keys())
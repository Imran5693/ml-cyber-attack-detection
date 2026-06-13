from pathlib import Path
from datetime import datetime
import pandas as pd
from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename

from utils.live_capture import LiveCapture
from utils.predictor_live import LiveTrafficPredictor

BASE_DIR = Path(__file__).resolve().parent

UPLOADS_DIR = BASE_DIR / "uploads"
OUTPUTS_DIR = BASE_DIR / "outputs"
REPORTS_DIR = OUTPUTS_DIR / "reports"
ALERTS_DIR = OUTPUTS_DIR / "alerts"
LOGS_DIR = OUTPUTS_DIR / "logs"

for folder in [UPLOADS_DIR, REPORTS_DIR, ALERTS_DIR, LOGS_DIR]:
    folder.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.secret_key = "ml_attack_detection_live_secret"

capture_engine = LiveCapture(str(BASE_DIR))
predictor = LiveTrafficPredictor(str(BASE_DIR))


def get_model_display_name(model_name: str) -> str:
    mapping = {
        "random_forest": "Random Forest",
        "svm": "SVM",
        "isolation_forest": "Isolation Forest"
    }
    return mapping.get(model_name, model_name)


def save_prediction_report(df: pd.DataFrame, prefix: str, model_name: str) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_model = secure_filename(model_name)
    report_path = REPORTS_DIR / f"{prefix}_{safe_model}_{timestamp}.csv"
    df.to_csv(report_path, index=False)
    return report_path


def analyze_attack_summary(result_df: pd.DataFrame) -> dict:
    if "prediction" not in result_df.columns:
        return {
            "attack_type": "Analysis Error",
            "severity": "Unknown",
            "top_source": "N/A",
            "top_target": "N/A",
            "attack_ratio": 0,
            "recommendation": "Prediction column missing from result."
        }

    total_rows = len(result_df)
    attack_df = result_df[result_df["prediction"] == 1].copy()
    attack_count = len(attack_df)

    if total_rows == 0 or attack_df.empty:
        return {
            "attack_type": "No Attack Detected",
            "severity": "Low",
            "top_source": "N/A",
            "top_target": "N/A",
            "attack_ratio": 0,
            "recommendation": "No immediate action required."
        }

    attack_ratio = round((attack_count / total_rows) * 100, 2)

    top_source = "Unknown"
    top_target = "Unknown"

    if "ip_src" in attack_df.columns and not attack_df["ip_src"].dropna().empty:
        top_source = attack_df["ip_src"].dropna().value_counts().idxmax()

    if "ip_dst" in attack_df.columns and not attack_df["ip_dst"].dropna().empty:
        top_target = attack_df["ip_dst"].dropna().value_counts().idxmax()

    if attack_count > 100000 or attack_ratio >= 80:
        attack_type = "Possible Hping / Flood Attack"
        severity = "Critical"
        recommendation = f"Investigate or block suspicious source {top_source}."
    elif attack_count > 10000 or attack_ratio >= 50:
        attack_type = "Possible DoS / Burst Attack"
        severity = "High"
        recommendation = f"Review traffic from {top_source} to {top_target}."
    elif attack_count > 1000 or attack_ratio >= 20:
        attack_type = "Suspicious High-Volume Activity"
        severity = "Medium"
        recommendation = "Monitor source and validate whether traffic is expected."
    else:
        attack_type = "Suspicious Traffic"
        severity = "Low"
        recommendation = "Review sample rows and confidence values."

    return {
        "attack_type": attack_type,
        "severity": severity,
        "top_source": top_source,
        "top_target": top_target,
        "attack_ratio": attack_ratio,
        "recommendation": recommendation
    }


def render_results(result_df, model_name, uploaded_file, show_only_attacks, prefix):
    total_rows = len(result_df)
    attack_count = int((result_df["prediction"] == 1).sum()) if "prediction" in result_df.columns else 0
    normal_count = int((result_df["prediction"] == 0).sum()) if "prediction" in result_df.columns else 0

    attack_summary = analyze_attack_summary(result_df)

    display_df = result_df.copy()
    if show_only_attacks and "prediction" in display_df.columns:
        display_df = display_df[display_df["prediction"] == 1].copy()

    preview_limit = 500
    if len(display_df) > preview_limit:
        display_df = display_df.head(preview_limit)

    report_path = save_prediction_report(result_df, prefix, model_name)

    return render_template(
        "results.html",
        model_name=get_model_display_name(model_name),
        total_rows=total_rows,
        attack_count=attack_count,
        normal_count=normal_count,
        showing_rows=len(display_df),
        preview_limit=preview_limit,
        show_only_attacks=show_only_attacks,
        columns=display_df.columns.tolist(),
        records=display_df.to_dict(orient="records"),
        uploaded_file=uploaded_file,
        saved_report=report_path.name,
        attack_summary=attack_summary
    )


@app.route("/", methods=["GET"])
def index():
    return render_template(
        "live_index.html",
        available_models=predictor.get_supported_models()
    )


@app.route("/upload-and-predict", methods=["POST"])
def upload_and_predict():
    try:
        file = request.files.get("file")
        model_name = request.form.get("model_name", "random_forest")
        show_only_attacks = request.form.get("show_only_attacks") == "on"

        if not file or file.filename == "":
            flash("CSV file is required.")
            return redirect(url_for("index"))

        filename = secure_filename(file.filename)

        if not filename.lower().endswith(".csv"):
            flash("Only CSV files are supported.")
            return redirect(url_for("index"))

        file_path = UPLOADS_DIR / filename
        file.save(file_path)

        result_df = predictor.predict_csv(str(file_path), model_name=model_name)

        return render_results(
            result_df=result_df,
            model_name=model_name,
            uploaded_file=filename,
            show_only_attacks=show_only_attacks,
            prefix="upload_report"
        )

    except Exception as e:
        print("Upload prediction error:", repr(e))
        flash(f"Upload prediction failed: {str(e)}")
        return redirect(url_for("index"))


@app.route("/capture-and-predict", methods=["POST"])
def capture_and_predict():
    try:
        interface = request.form.get("interface", "").strip()
        duration_raw = request.form.get("duration", "10")
        model_name = request.form.get("model_name", "random_forest")
        show_only_attacks = request.form.get("show_only_attacks") == "on"

        if not interface:
            flash("Interface is required.")
            return redirect(url_for("index"))

        try:
            duration = int(duration_raw)
        except ValueError:
            flash("Capture duration must be a valid number.")
            return redirect(url_for("index"))

        if duration < 3 or duration > 120:
            flash("Capture duration must be between 3 and 120 seconds.")
            return redirect(url_for("index"))

        csv_path = capture_engine.capture_to_csv(
            interface=interface,
            duration=duration,
            output_prefix="live_capture"
        )

        result_df = predictor.predict_csv(str(csv_path), model_name=model_name)

        return render_results(
            result_df=result_df,
            model_name=model_name,
            uploaded_file=csv_path.name,
            show_only_attacks=show_only_attacks,
            prefix="live_report"
        )

    except Exception as e:
        print("Live capture error:", repr(e))
        flash(f"Live capture failed: {str(e)}")
        return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5001)
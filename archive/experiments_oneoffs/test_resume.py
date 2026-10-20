# Manual script (NOT a pytest test): runs the real parallel harness with --limit 1, which makes a live Gemini API call.


def main() -> None:
    import json
    import subprocess
    import sys
    from pathlib import Path

    # Create a checkpoint with 2 good records and 1 error record.
    with open("GUIDE_Dataset/processed/guide_sample_500_alerts.json", encoding="utf-8") as f:
        alerts = json.load(f)

    with open("GUIDE_Dataset/processed/guide_n50_scaleup_320_alerts.json", encoding="utf-8") as f:
        contam = json.load(f)

    contam_ids = {str(c["alert_id"]) for c in contam}

    with open("experiments/paired_clean_results_B.json", encoding="utf-8") as f:
        main_results = json.load(f)
    main_done_ids = {str(r["alert_id"]) for r in main_results}

    # Pick 3 alerts that are in contam but NOT in main_done_ids
    selected_alerts = [a for a in alerts if str(a["alert_id"]) in contam_ids and str(a["alert_id"]) not in main_done_ids][:3]

    checkpoint = [
        {
            "alert_id": selected_alerts[0]["alert_id"],
            "condition": "clean",
            "sse_results": [{"verdict": "FEASIBLE"}],
        },
        {
            "alert_id": selected_alerts[1]["alert_id"],
            "condition": "clean",
            "sse_results": [{"verdict": "INFEASIBLE"}],
        },
        {
            "alert_id": selected_alerts[2]["alert_id"],
            "condition": "clean",
            "nce_error": "Fake API Error",
        }
    ]

    scratch = Path("experiments/scratch_resume.json")
    with open(scratch, "w", encoding="utf-8") as f:
        json.dump(checkpoint, f, indent=2)

    print("Starting resume test...", flush=True)

    # Run parallel harness
    proc = subprocess.run([sys.executable, "-m", "experiments.run_paired_clean_eval_B_parallel", "--scratch", "scratch_resume.json", "--limit", "1"], capture_output=True, text=True)
    print("--- STDOUT ---")
    print(proc.stdout)
    print("--- STDERR ---")
    print(proc.stderr)

    # Verify
    with open(scratch, encoding="utf-8") as f:
        final = json.load(f)

    print("--- FINAL CHECKPOINT ---")
    for r in final:
        aid = str(r["alert_id"])
        has_sse = r.get("sse_results") is not None
        has_err = r.get("nce_error") is not None
        print(f"Alert {aid}: has_sse={has_sse}, has_err={has_err}, keys={len(r.keys())}")
    print(f"Total records in final checkpoint: {len(final)}")


if __name__ == "__main__":
    main()

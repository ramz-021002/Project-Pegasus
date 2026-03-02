import sys
import os
import time
import uuid
import json

sys.path.append(os.path.join(os.getcwd(), "backend"))

from app.database import SessionLocal, DatabaseOperations, SampleStatus, AnalysisStatus
from app.tasks.orchestration import analyze_sample

SAMPLE_ID = "ed8ee6ac-ed52-47a2-a718-049f04bc9ff5"


def trigger_reanalysis():
    db = SessionLocal()
    try:
        sample_uuid = uuid.UUID(SAMPLE_ID)
        sample = DatabaseOperations.get_sample_by_id(db, sample_uuid)

        if not sample:
            print(f"Sample {SAMPLE_ID} not found!")
            return

        print(
            f"Triggering re-analysis for sample: {sample.original_filename} ({sample.id})"
        )

        sample.status = SampleStatus.ANALYZING
        for result in sample.analysis_results:
            result.status = AnalysisStatus.RUNNING
            result.results_json = None
            result.error_message = None
        db.commit()

        task = analyze_sample.apply_async(args=[SAMPLE_ID])
        print(f"Task submitted. Task ID: {task.id}")

        print("Waiting for analysis to complete...")
        for i in range(120):
            db.refresh(sample)
            print(f"Status: {sample.status.value}")

            if (
                sample.status == SampleStatus.COMPLETED
                or sample.status == SampleStatus.FAILED
            ):
                break

            time.sleep(2)

        print(f"Final Status: {sample.status.value}")

        for r in sample.analysis_results:
            print(f"Analysis: {r.analysis_type.value}")
            print(f"Status: {r.status.value}")
            if r.results_json:
                print(f"Results keys: {list(r.results_json.keys())}")
                if "errors" in r.results_json:
                    print(f"Errors: {r.results_json['errors']}")
                if "behavior_summary" in r.results_json:
                    print(f"Behavior: {r.results_json['behavior_summary']}")

    finally:
        db.close()


if __name__ == "__main__":
    trigger_reanalysis()

import sys
import os
import time
import uuid
import json

# Add backend to path
sys.path.append(os.path.join(os.getcwd(), 'backend'))

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

        print(f"Triggering re-analysis for sample: {sample.original_filename} ({sample.id})")
        
        # Reset sample status
        sample.status = SampleStatus.ANALYZING
        for result in sample.analysis_results:
            result.status = AnalysisStatus.RUNNING
            result.results_json = None
            result.error_message = None
        db.commit()
        
        # Call Celery task (synchronously for testing if possible, or async and poll)
        # analyze_sample is a celery task. We can call it directly as a function since we are in the same codebase, 
        # BUT it depends on celery semantics?
        # The `analyze_sample` function uses `run_static_analysis.s(...)` which returns signatures.
        # Calling it directly `analyze_sample(SAMPLE_ID)` might just return the chain object or execute it?
        # `analyze_sample` is decorated with `@celery_app.task`.
        # Calling `analyze_sample(SAMPLE_ID)` creates a task instance?
        # Let's use `apply_async` or just call the logic manually if we want to confirm it works *now*.
        
        # Actually, let's just use `analyze_sample.apply(args=[SAMPLE_ID])` to run it in-process (if eager is set) 
        # or just `.delay()` and poll DB.
        # Since we're in a container, lets use `.apply()` to try and run it synchronously-ish if possible, 
        # but the chain logic might require a worker.
        # Safest is to just call the underlying logic steps manually to debug, or rely on the system.
        
        # Let's trust the system and use the task.
        task = analyze_sample.apply_async(args=[SAMPLE_ID])
        print(f"Task submitted. Task ID: {task.id}")
        
        # Poll DB for completion
        print("Waiting for analysis to complete...")
        for i in range(120): # Wait up to 2 minutes
            db.refresh(sample)
            print(f"Status: {sample.status.value}")
            
            if sample.status == SampleStatus.COMPLETED or sample.status == SampleStatus.FAILED:
                break
                
            # Also check individual analysis results
            # for r in sample.analysis_results:
            #     print(f"  - {r.analysis_type.value}: {r.status.value}")
            
            time.sleep(2)
            
        print(f"Final Status: {sample.status.value}")
        
        # Print results
        for r in sample.analysis_results:
            print(f"Analysis: {r.analysis_type.value}")
            print(f"Status: {r.status.value}")
            if r.results_json:
                print(f"Results keys: {list(r.results_json.keys())}")
                if 'errors' in r.results_json:
                     print(f"Errors: {r.results_json['errors']}")
                if 'behavior_summary' in r.results_json:
                    print(f"Behavior: {r.results_json['behavior_summary']}")
                    
    finally:
        db.close()

if __name__ == "__main__":
    trigger_reanalysis()

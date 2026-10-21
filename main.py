"""
SOC-AI Orchestrator
-------------------
Coordinates the whole SOC-AI pipeline and runs it sequentially from start to
finish. The system re-runs every 3 minutes so logs are refreshed continuously
and a Heartbeat notification is sent to Telegram whenever no new alert appears
within the 3-minute window, regardless of whether new logs arrived.

Usage:
    python main.py
"""

# --- 1. LOAD ENVIRONMENT BEFORE IMPORTING OTHER MODULES ---
from dotenv import load_dotenv
load_dotenv()  # Ensure API keys are set before soc_ai is imported

import os
import sys
import time
import logging
from datetime import datetime

# Ensure Python can import modules from the project root
sys.path.insert(0, os.getcwd())

# --- 2. IMPORT PIPELINES ---
from soc_ai.normalized.pipeline import normalize_pipeline
from soc_ai.dedup.pipeline import dedup_pipeline
from soc_ai.enrichment.pipeline import enrich_pipeline
from soc_ai.aggregation.pipeline import aggregate_pipeline
from soc_ai.ai.pipeline import analyze_pipeline
from soc_ai.alert.pipeline import alert_pipeline
from soc_ai.telegram.pipeline import telegram_pipeline

# --- 3. PATH CONFIGURATION ---
# Raw log file (rename this if the source file changes)
RAW_LOG_FILE = "raw_logs/03_fortigate_firewall.txt" 
OUTPUT_DIR = "output"

# Intermediate output files
NORM_OUT = os.path.join(OUTPUT_DIR, "normalized_fortigate.jsonl")
DEDUP_OUT = os.path.join(OUTPUT_DIR, "deduplicated_fortigate.jsonl")
ENRICH_OUT = os.path.join(OUTPUT_DIR, "enriched_fortigate.jsonl")
AGG_OUT = os.path.join(OUTPUT_DIR, "aggregated_fortigate.jsonl")
AI_OUT = os.path.join(OUTPUT_DIR, "analyzed_fortigate.jsonl")
ALERT_OUT = os.path.join(OUTPUT_DIR, "alerts_fortigate.jsonl")

# --- 4. TIMING CONFIGURATION ---
# Pipeline cycle in seconds: the loop re-runs every 3 minutes.
INTERVAL_SECONDS = 180

# Tumbling aggregation window in minutes. Kept equal to the cycle length so each
# run covers exactly the logs collected since the previous run.
WINDOW_MINUTES = 3

# Heartbeat interval in hours (3 minutes). A HeartbeatEvent is emitted when no
# new alert has been produced within this period, even if no new log arrived.
HEARTBEAT_INTERVAL_HOURS = 3 / 60

# --- 5. LOGGING SETUP ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-7s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler("soc_ai_orchestrator.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)

def run_pipeline_cycle():
    """Run the full pipeline from Normalize through Telegram."""
    logging.info(f"=== CYCLE STARTED AT: {datetime.now().strftime('%H:%M:%S')} ===")
    start_time = time.time()
    
    try:
        # 1. Normalize
        logging.info("[1/7] Normalizing logs (Normalize)...")
        normalize_pipeline(RAW_LOG_FILE, NORM_OUT)
        
        # 2. Deduplicate
        logging.info("[2/7] Removing duplicates (Deduplicate)...")
        dedup_pipeline(NORM_OUT, DEDUP_OUT)
        
        # 3. Enrichment
        logging.info("[3/7] Enriching data (Enrichment)...")
        enrich_pipeline(DEDUP_OUT, ENRICH_OUT)
        
        # 4. Aggregate (group into 3-minute windows)
        logging.info("[4/7] Grouping logs (Aggregate)...")
        aggregate_pipeline(ENRICH_OUT, AGG_OUT, window_minutes=WINDOW_MINUTES)
        
        # 5. AI Analysis
        logging.info("[5/7] Analyzing with AI (LLM Analysis)...")
        analyze_pipeline(AGG_OUT, AI_OUT)
        
        # 6. Alert Detection
        # heartbeat_interval_hours = 3/60 (i.e. 3 minutes).
        # Forces a HeartbeatEvent when no new alert appeared for 3 minutes.
        logging.info("[6/7] Detecting alerts & Heartbeat (every 3 minutes)...")
        alert_pipeline(
            AI_OUT, 
            ALERT_OUT, 
            heartbeat_interval_hours=HEARTBEAT_INTERVAL_HOURS, 
            reset_state=False
        )
        
        # 7. Send to Telegram
        # Pass dry_run=None so it reads TELEGRAM_DRY_RUN from the .env file
        logging.info("[7/7] Sending notifications to Telegram...")
        telegram_pipeline(ALERT_OUT, dry_run=None)
        
        elapsed = time.time() - start_time
        logging.info(f"=== CYCLE COMPLETED (took {elapsed:.2f} seconds) ===\n")
        
    except Exception as e:
        logging.error(f"!!! CRITICAL ERROR IN CYCLE: {e}", exc_info=True)

def main():
    """Main loop of the system."""
    logging.info("Starting SOC-AI Orchestrator...")
    logging.info(f"The pipeline runs continuously every {INTERVAL_SECONDS//60} minutes.")
    logging.info("Note: make sure the .env file has valid API keys and Telegram bot settings.")
    
    # Create the output directory if it does not exist
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Infinite loop to run periodically
    while True:
        cycle_start = time.time()
        
        run_pipeline_cycle()
        
        cycle_duration = time.time() - cycle_start
        
        # Compute the remaining sleep time so the cycle length stays exact
        sleep_time = max(0, INTERVAL_SECONDS - cycle_duration)
        if sleep_time > 0:
            logging.info(f"Waiting {sleep_time:.0f} seconds before the next cycle...\n")
            time.sleep(sleep_time)

if __name__ == "__main__":
    main()
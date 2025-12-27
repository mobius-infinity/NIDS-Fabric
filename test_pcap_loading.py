#!/usr/bin/env python3
"""
Test script to verify PCAP metadata loading on startup
"""

import sys
import os

# Add app to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from app.globals import PCAP_METADATA, load_pcap_metadata_from_csv

# Create app context
app = create_app()

with app.app_context():
    print("\n" + "="*60)
    print("TESTING PCAP METADATA LOADING")
    print("="*60)
    
    # Check if metadata file exists
    pcap_info_folder = app.config.get('PCAP_INFO_FOLDER')
    metadata_path = os.path.join(pcap_info_folder, 'metadata_pcaps.csv')
    
    print(f"\n[1] Metadata file location: {metadata_path}")
    print(f"[2] File exists: {os.path.exists(metadata_path)}")
    
    # Load metadata
    print(f"\n[3] Loading PCAP metadata from CSV...")
    load_pcap_metadata_from_csv(app)
    
    # Show results
    print(f"\n[4] Cache content:")
    print(f"    Total records in PCAP_METADATA: {len(PCAP_METADATA)}")
    
    if PCAP_METADATA:
        print(f"\n[5] Sample records:")
        for i, (pcap_name, metadata) in enumerate(list(PCAP_METADATA.items())[:3]):
            print(f"    - {pcap_name}:")
            print(f"      Size: {metadata.get('size_mb')} MB")
            print(f"      Flows: {metadata.get('total_flows')} total, {metadata.get('threat_flows')} threat, {metadata.get('safe_flows')} safe")
            print(f"      Is Threat: {metadata.get('is_threat')}")
            print(f"      Date: {metadata.get('analysis_date')}")
    else:
        print("    [WARNING] No PCAP metadata found in cache!")
    
    print("\n" + "="*60)
    print("TEST COMPLETED")
    print("="*60 + "\n")

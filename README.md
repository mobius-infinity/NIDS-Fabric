# NIDS-Fabric

A hybrid network intrusion detection system combining machine learning (6 ML models with consensus voting) and IPS engine with TLS fingerprint matching via JA3, JA3S, and SNI.

## Motivation & Problem Statement

### Current limitations of traditional IDS

Modern firewalls rely on signature-based IDS rules to detect attacks. While these rules are highly effective at detecting known threats, they have critical limitations:

**Limited against new attacks:** IDS rules are based on signatures of known attacks. Any novel or zero-day attack bypasses these rules entirely.

**Impractical update cycles:** Continuous rule updates are infeasible. A single missed update window (even 1 second) can allow attackers to infiltrate systems.

**Reactive defense:** By the time new signatures are created and deployed, attacks may have already succeeded.

### NIDS-Fabric solution

NIDS-Fabric addresses these limitations by combining machine learning with IDS rules. Rather than relying solely on attack signatures, the system learns behavioral patterns from historical data.

**Proactive detection:** ML models identify novel and zero-day attacks without waiting for signature updates.

**Hybrid approach:** ML consensus voting (6 models) identifies suspicious flows, while IPS TLS fingerprinting (JA3, JA3S, SNI) verifies and confirms detections.

**Beyond traditional NGFW:** Unlike next-generation firewalls that use ML only for malware detection in files, NIDS-Fabric applies ML to network traffic analysis, providing comprehensive threat detection at the flow level.

## Features

**Hybrid detection:** ML voting (Random Forest, LightGBM, DNN) combined with IPS TLS fingerprint verification

**6 ML models:** Random Forest, LightGBM, and DNN (binary and multiclass variants) all trained in-house

**Consensus voting:** Configurable threshold (1-6 votes) for flexible detection sensitivity

**IPS engine:** TLS fingerprint matching via JA3 client hash, JA3S server hash, and SNI domain detection

**Real-time dashboard:** CPU and RAM monitoring, threat statistics, and live flow analysis

**PCAP analysis:** Automatic processing via nProbe with 53 network features extracted per flow

**Evidence management:** Threat files preserved for forensics while safe files are automatically deleted to save storage

## Performance & System Requirements

### Detection capability

**Known attack detection:** Excellent accuracy on known attack patterns from training data

**Novel attack detection:** Good capability to identify suspicious behavioral patterns without prior signatures

### System resources (Intel i5 10th Gen)

**CPU usage:** Approximately 10% during active PCAP analysis

**RAM usage:** Varies based on network traffic volume and number of concurrent flows

**Storage:** Minimal footprint with only threat evidence files preserved and safe files automatically deleted

> This is an early-stage project. Performance metrics are preliminary and subject to optimization in future releases.

## Machine Learning Models

All machine learning models are trained in-house by the project team.

**Random Forest:** Fast and interpretable tree-based ensemble learning with binary classification (Attack/Benign) and multiclass classification (Attack types).

**Light Gradient Boosting Machine:** LightGBM provides optimized gradient boosting for efficient learning with binary and multiclass classification capabilities.

**Deep Neural Network:** Deep learning model for complex pattern recognition using binary and multiclass classification approaches.

### Consensus voting strategy

All 6 models vote simultaneously. The system uses configurable thresholds (1-6 votes) to classify flows:

**High confidence:** 5 or more votes trigger immediate alert, skipping IPS verification

**Medium confidence:** Votes meet threshold but below 5, triggering IPS verification to confirm or deny

**Low confidence:** Fewer votes than threshold, allowing IPS to catch false negatives

## Project Architecture

See [PROJECT_ARCHITECTURE.md](PROJECT_ARCHITECTURE.md) for detailed system diagrams and flows covering:

**Application startup:** Flask app initialization, database setup, and background thread management

**PCAP analysis pipeline:** nProbe feature extraction, ML consensus voting, hybrid detection, and comprehensive logging

**ML engine:** Model caching, disk loading, and distributed prediction across the workflow

**IPS engine:** TLS fingerprint matching logic using JA3 hashes and SNI domain patterns

**Hybrid detection logic:** Decision tree combining ML confidence scores with IPS verification results

**API layer:** RESTful endpoints for file management, PCAP upload, log retrieval, and system configuration

**Storage structure:** Organized file hierarchy for logs, evidence PCaps, and metadata

**Complete flow summary:** End-to-end PCAP processing from upload through detection and storage

**Data flow:** Component interactions and information flow visualized via sequence diagrams

**System configuration:** Dynamic state management for detection modes and sensitivity settings

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

**Copyright © 2025 mobius-infinity. All rights reserved.**

You are free to use, modify, and distribute this software, but you must retain the original copyright notice.

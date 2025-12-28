# NIDS-Fabric

A Hybrid Network Intrusion Detection System combining Machine Learning - 6 ML models with consensus voting and IPS Engine -TLS Fingerprint matching via JA3/JA3S/SNI.

## Motivation & Problem Statement

### Current Limitations of Traditional IDS

Modern firewalls rely on signature-based IDS rules to detect attacks. While these rules are highly effective at detecting known threats, they have critical limitations:

- **Limited Against New Attacks**: IDS rules are based on signatures of known attacks. Any novel or zero-day attack bypasses these rules entirely.
- **Impractical Update Cycles**: Continuous rule updates are infeasible. A single missed update window—even 1 second—can allow attackers to infiltrate systems.
- **Reactive Defense**: By the time new signatures are created and deployed, attacks may have already succeeded.

### NIDS-Fabric Solution

NIDS-Fabric addresses these limitations by combining **machine learning** with **IDS rules**:

- **Proactive Detection**: ML models learn attack patterns from historical data, enabling detection of novel and zero-day attacks without waiting for signature updates.
- **Hybrid Approach**: ML consensus voting (6 models) identifies suspicious flows, while IPS TLS fingerprinting (JA3, JA3S, SNI) verifies and confirms detections.
- **Beyond Traditional NGFW**: Unlike next-generation firewalls (NGFW) that use ML only for malware detection in files, NIDS-Fabric applies ML to **network traffic analysis**, providing comprehensive threat detection at the flow level.

## Features

- **Hybrid Detection**: ML voting (RF, LightGBM, DNN) + IPS TLS fingerprint verification
- **6 ML Models**: Random Forest, LightGBM, DNN (binary + multiclass) - all trained in-house
- **Consensus Voting**: Configurable threshold (1-6 votes) for flexible detection sensitivity
- **IPS Engine**: TLS fingerprint matching via JA3 Client, JA3S Server, and SNI domain detection
- **Real-time Dashboard**: CPU/RAM monitoring, threat statistics, live flow analysis
- **PCAP Analysis**: Automatic processing via nProbe with 53 network features
- **Evidence Management**: Threat files preserved for forensics, safe files auto-deleted to save storage

## Performance & System Requirements

### Detection Capability
- **Known Attack Detection**: Excellent - High accuracy on known attack patterns
- **Novel Attack Detection**: Good - ML models can identify suspicious behavioral patterns

### System Resources (Intel i5 10th Gen)
- **CPU Usage**: ~10% during active PCAP analysis
- **RAM Usage**: Varies based on network traffic volume and concurrent flows
- **Storage**: Minimal - only threat evidence files preserved, safe files automatically deleted

> **Note**: This is an early-stage project. Performance metrics are preliminary and subject to optimization in future releases.

## Machine Learning Models

All machine learning models are **trained in-house** by the project team:

- **Random Forest**: Fast, interpretable tree-based ensemble learning
  - Binary classification (Attack/Benign)
  - Multiclass classification (Attack types)

- **Light Gradient Boosting Machine (LightGBM)**: Optimized gradient boosting for efficient learning
  - Binary classification
  - Multiclass classification

- **Deep Neural Network (DNN)**: Deep learning model for complex pattern recognition
  - Binary classification
  - Multiclass classification

### Consensus Voting Strategy
All 6 models vote simultaneously. The system uses configurable thresholds (1-6 votes) to classify flows:
- **High Confidence (≥5 votes)**: Immediate alert, skip IPS verification
- **Medium Confidence (≥threshold)**: IPS verification confirms or denies
- **Low Confidence (<threshold)**: IPS can catch false negatives

## Project Architecture

See [PROJECT_ARCHITECTURE.md](PROJECT_ARCHITECTURE.md) for detailed system diagrams and flows:

- **Application Startup** - Flask app initialization, database, thread management
- **PCAP Analysis Pipeline** - nProbe extraction, ML voting, hybrid detection, logging
- **ML Engine** - Model caching, loading, and prediction
- **IPS Engine** - TLS fingerprint matching (JA3, JA3S, SNI)
- **Hybrid Detection Logic** - Decision tree combining ML + IPS
- **API Layer** - RESTful endpoints for file management and analysis
- **Storage Structure** - Organized file hierarchy for logs and evidence
- **Complete Flow Summary** - End-to-end processing workflow
- **Data Flow** - Component interactions via sequence diagrams
- **System Configuration** - Dynamic state management for detection modes

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**Copyright © 2025 mobius-infinity. All rights reserved.**

You are free to use, modify, and distribute this software, but you must retain the original copyright notice.

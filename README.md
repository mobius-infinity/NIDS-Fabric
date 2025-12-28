# NIDS-Fabric

A Hybrid Network Intrusion Detection System combining Machine Learning (6 ML models with consensus voting) and IPS Engine (TLS Fingerprint matching via JA3/JA3S/SNI).

## Features

- **Hybrid Detection**: ML voting (RF, LightGBM, DNN) + IPS TLS fingerprint verification
- **6 ML Models**: Random Forest, LightGBM, DNN (binary + multiclass)
- **Consensus Voting**: Configurable threshold (1-6 votes)
- **IPS Engine**: JA3, JA3S, SNI matching for TLS traffic
- **Real-time Dashboard**: CPU/RAM monitoring, threat statistics
- **PCAP Analysis**: Automatic processing via nProbe
- **Evidence Management**: Threat files preserved, safe files auto-deleted

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**Copyright © 2025 mobius-infinity. All rights reserved.**

You are free to use, modify, and distribute this software, but you must retain the original copyright notice.

# NIDS Fabric - Project Architecture (Mermaid Diagrams)

## 1. APPLICATION STARTUP FLOW

```mermaid
graph TD
    A["run.py<br/>Application Entry"] --> B["create_app()"]
    B --> C["Flask Configuration"]
    C --> D["Initialize SQLAlchemy"]
    D --> E["Initialize LoginManager"]
    E --> F["Initialize IPS Engine"]
    F --> G["Register Blueprints<br/>auth, api, main"]
    
    G --> H["create_folders()"]
    H --> I["Create storage/incoming/<br/>storage/evidence/<br/>storage/logs/..."]
    
    I --> J["init_db_data()"]
    J --> J1["db.create_all()"]
    J1 --> J2["Create admin user"]
    J2 --> J3["Load SYSTEM_CONFIG from DB"]
    J3 --> J4["load_pcap_metadata_from_csv()"]
    J4 --> J5["load_ips_rules_from_csv()"]
    
    J5 --> K["init_system_logger()"]
    K --> L["Start Background Threads"]
    L --> L1["thread_system_stats()"]
    L --> L2["thread_pcap_worker()"]
    
    L1 --> M["app.run()"]
    L2 --> M
    M --> N["Server Running on :5000"]
    
    style A fill:#ff9d4d
    style M fill:#10b981
    style N fill:#10b981
```

---

## 2. PCAP ANALYSIS PIPELINE

```mermaid
graph TD
    A["User Upload PCAP<br/>POST /api/upload_pcap"] --> B["Save to storage/incoming/"]
    B --> C["FILE_STATUS = Pending"]
    
    C --> D["thread_pcap_worker()" ]
    D --> D1["Poll incoming/ every 2s"]
    
    D1 --> E["STEP 1: PCAP → CSV<br/>nprobe extraction"]
    E --> E1["Extract 53 features:<br/>IP, Port, Bytes, JA3C, JA3S, SNI..."]
    
    E1 --> F["STEP 2: ML VOTING<br/>6 Models"]
    F --> F1["Random Forest Binary"]
    F --> F2["Random Forest Multiclass"]
    F --> F3["LightGBM Binary"]
    F --> F4["LightGBM Multiclass"]
    F --> F5["DNN Binary"]
    F --> F6["DNN Multiclass"]
    
    F1 --> G["Accumulate Votes<br/>votes = 0-6"]
    F2 --> G
    F3 --> G
    F4 --> G
    F5 --> G
    F6 --> G
    
    G --> H["STEP 3: HYBRID DETECTION<br/>ML + IPS"]
    H --> H1["votes >= 5?<br/>ML_HIGH_THREAT"]
    H --> H2["votes >= threshold?<br/>ML_IPS_CONFIRMED/<br/>ML_UNCONFIRMED"]
    H --> H3["votes < threshold?<br/>IPS_FALSE_NEGATIVE/<br/>VERIFIED_BENIGN"]
    
    H1 --> I["STEP 4: LOGGING"]
    H2 --> I
    H3 --> I
    
    I --> I1["Consensus_Voting.csv"]
    I --> I2["IPS_Detections.csv"]
    I --> I3["Model Logs<br/>6 files"]
    
    I1 --> J["STEP 5: FILE DISPOSITION"]
    I2 --> J
    I3 --> J
    
    J --> J1["is_threat?"]
    J1 -->|YES| J2["Move to evidence_pcaps/"]
    J1 -->|NO| J3["Delete PCAP<br/>Save metadata only"]
    
    J2 --> K["FILE_STATUS = Done Threat"]
    J3 --> K["FILE_STATUS = Done Safe"]
    K --> L["Dashboard Updates"]
    
    style A fill:#3b82f6
    style E fill:#f59e0b
    style F fill:#f59e0b
    style H fill:#ef4444
    style I fill:#10b981
    style L fill:#10b981
```

---

## 3. ML ENGINE - MODEL CACHE SYSTEM

```mermaid
graph TD
    A["get_model<br/>RF/LGBM/DNN, binary/multiclass"] --> B["Check RAM Cache"]
    B --> B1{Found?}
    
    B1 -->|YES| C["Return cached<br/>model, scaler, encoder"]
    B1 -->|NO| D["Load from disk"]
    
    D --> D1{Model Type?}
    D1 -->|RF| D2["joblib.load<br/>rf_binary_model.joblib"]
    D1 -->|LGBM| D3["lgb.Booster<br/>lightgbm_binary.txt"]
    D1 -->|DNN| D4["tf.keras.load<br/>dnn_binary.keras"]
    
    D2 --> E["Load Scaler<br/>if needed"]
    D3 --> E
    D4 --> E
    
    E --> F["Load Encoder<br/>if multiclass"]
    F --> G["Cache in RAM"]
    G --> C
    C --> H["Return to Worker"]
    
    style A fill:#3b82f6
    style C fill:#10b981
    style H fill:#10b981
```

---

## 4. IPS ENGINE - TLS FINGERPRINT MATCHING

```mermaid
graph TD
    A["IPS Engine Load"] --> B["Load ips_rules.csv"]
    B --> C["Store in memory<br/>self.rules = []"]
    
    D["Flow Data"] --> E["match_flow()"]
    E --> E1["Extract JA3C, JA3S, SNI"]
    
    E1 --> F["Loop through rules"]
    F --> G["_check_rule_match()"]
    
    G --> G1{Priority 1:<br/>JA3 Match?}
    G1 -->|YES| H["return matched:True<br/>match_type:JA3"]
    G1 -->|NO| G2{Priority 2:<br/>JA3S Match?}
    
    G2 -->|YES| H
    G2 -->|NO| G3{Priority 3:<br/>SNI Match?}
    
    G3 -->|YES| H
    G3 -->|NO| I["continue to<br/>next rule"]
    I --> F
    
    F -.->|No rules match| J["return matched:False"]
    H --> K["Return rule info<br/>rule_id, rule_name,<br/>severity, category"]
    J --> K
    
    style G1 fill:#ef4444
    style G2 fill:#f59e0b
    style G3 fill:#3b82f6
    style K fill:#10b981
```

---

## 5. HYBRID DETECTION LOGIC

```mermaid
graph TD
    A["Input: votes 0-6"] --> B["Calculate masks"]
    B --> B1["high_threat_mask = votes >= 5"]
    B --> B2["medium_mask = votes >= threshold AND < 5"]
    B --> B3["low_mask = votes < threshold"]
    
    B1 --> C["Process HIGH THREAT"]
    C --> C1["decision = 1 ATTACK"]
    C1 --> C2["source = ML_HIGH_THREAT"]
    C2 --> C3["Skip IPS check"]
    
    B2 --> D["Process MEDIUM"]
    D --> D1["Check IPS match?"]
    D1 -->|IPS Match| D2["decision = 1 ATTACK"]
    D2 --> D3["source = ML_IPS_CONFIRMED"]
    D1 -->|No Match| D4["decision = 1 ATTACK"]
    D4 --> D5["source = ML_UNCONFIRMED"]
    
    B3 --> E["Process LOW BENIGN"]
    E --> E1["Check IPS match?"]
    E1 -->|IPS Match| E2["decision = 1 ATTACK"]
    E2 --> E3["source = IPS_FALSE_NEGATIVE"]
    E1 -->|No Match| E4["decision = 0 BENIGN"]
    E4 --> E5["source = VERIFIED_BENIGN"]
    
    C3 --> F["Output:<br/>final_decisions[]<br/>detection_sources[]<br/>ips_matches[]"]
    D3 --> F
    D5 --> F
    E3 --> F
    E5 --> F
    
    style C fill:#ef4444
    style D fill:#f59e0b
    style E fill:#3b82f6
    style F fill:#10b981
```

---

## 6. API LAYER - ENDPOINTS

```mermaid
graph TD
    subgraph SYSTEM["System & Status"]
        A["GET /api/status"]
        B["GET /api/history"]
        C["GET /api/system-settings"]
        D["POST /api/system-settings"]
    end
    
    subgraph FILES["File Management"]
        E["GET /api/incoming-files"]
        F["POST /api/upload_pcap"]
        G["POST /api/delete-file"]
        H["POST /api/delete-evidence-pcap"]
    end
    
    subgraph LOGS["Logs & Analysis"]
        I["GET /api/get_flows"]
        J["GET /api/get_consensus_logs"]
        K["GET /api/ips-logs"]
        L["GET /api/logs/summary"]
    end
    
    subgraph IPS["IPS Management"]
        M["GET /api/ips-rules"]
        N["POST /api/ips-rules/add-ja3"]
        O["POST /api/ips-rules/import-file"]
        P["DELETE /api/ips-rules/<id>"]
        Q["GET /api/ips-sources"]
        R["POST /api/ips-sources"]
    end
    
    A -.-> |CPU/RAM/Flows| Dashboard
    E -.-> |PCAP List| Dashboard
    I -.-> |Detection Logs| Dashboard
    M -.-> |IPS Rules| Dashboard
    
    style Dashboard fill:#10b981
```

---

## 7. STORAGE STRUCTURE

```mermaid
graph TD
    A["storage/"] --> B["incoming_pcaps/"]
    A --> C["evidence_pcaps/"]
    A --> D["processed_pcaps/"]
    A --> E["model_logs/"]
    A --> F["info_pcaps/"]
    A --> G["ips/"]
    A --> H["temp_uploads/"]
    
    B --> B1["*.pcap, *.pcapng<br/>User uploads<br/>Worker polls"]
    
    C --> C1["threat_files.pcap<br/>Preserved evidence<br/>Can be downloaded"]
    
    D --> D1["Safe files<br/>(Optional)"]
    
    E --> E1["DNN_binary.csv<br/>DNN_multiclass.csv<br/>LightGBM_binary.csv<br/>LightGBM_multiclass.csv<br/>RF_binary.csv<br/>RF_multiclass.csv<br/>Consensus_Voting.csv<br/>IPS_Detections.csv"]
    
    F --> F1["metadata_pcaps.csv<br/>PCAP history"]
    
    G --> G1["ips_rules.csv<br/>Main rules DB<br/>ips_sources.csv<br/>Rule sources"]
    
    H --> H1["Temporary<br/>nprobe output<br/>Auto cleanup"]
    
    style B fill:#3b82f6
    style C fill:#ef4444
    style E fill:#f59e0b
    style F fill:#10b981
    style G fill:#22c55e
```

---

## 8. COMPLETE FLOW SUMMARY

```mermaid
graph TB
    subgraph STARTUP["1. APPLICATION STARTUP"]
        S1["run.py"]
        S2["create_app()"]
        S3["init_db_data()"]
        S4["Start Threads"]
        
        S1 --> S2 --> S3 --> S4
    end
    
    subgraph UPLOAD["2. USER ACTION"]
        U1["Upload PCAP<br/>Web UI"]
        U2["POST /api/upload_pcap"]
        U3["Save to incoming/"]
        
        U1 --> U2 --> U3
    end
    
    subgraph QUEUE["3. WORKER DETECTS"]
        Q1["thread_pcap_worker()"]
        Q2["Poll incoming/ every 2s"]
        Q3["FILE_STATUS = Analyzing"]
        
        Q1 --> Q2 --> Q3
    end
    
    subgraph ANALYSIS["4. PCAP ANALYSIS"]
        A1["nprobe: PCAP → CSV"]
        A2["6 Models Vote"]
        A3["Hybrid Detection<br/>ML + IPS"]
        A4["Calculate Final Decision"]
        
        A1 --> A2 --> A3 --> A4
    end
    
    subgraph LOGGING["5. LOGGING"]
        L1["Consensus_Voting.csv"]
        L2["IPS_Detections.csv"]
        L3["Model Logs 6x"]
        L4["PCAP metadata"]
        
        L1 --> L2 --> L3 --> L4
    end
    
    subgraph DISPOSITION["6. FILE DISPOSITION"]
        D1{Has Threat?}
        D2["Move to evidence/"]
        D3["Delete PCAP"]
        
        D1 -->|YES| D2
        D1 -->|NO| D3
    end
    
    subgraph UI["7. UI UPDATE"]
        UI1["Frontend polls /api/status"]
        UI2["Dashboard refreshes<br/>real-time"]
        
        UI1 --> UI2
    end
    
    STARTUP --> UPLOAD
    UPLOAD --> QUEUE
    QUEUE --> ANALYSIS
    ANALYSIS --> LOGGING
    LOGGING --> DISPOSITION
    DISPOSITION --> UI
    
    style STARTUP fill:#ff9d4d
    style UPLOAD fill:#3b82f6
    style QUEUE fill:#3b82f6
    style ANALYSIS fill:#f59e0b
    style LOGGING fill:#10b981
    style DISPOSITION fill:#ef4444
    style UI fill:#22c55e
```

---

## 9. DATA FLOW - SINGLE PCAP PROCESSING

```mermaid
sequenceDiagram
    participant User
    participant Web as Web UI
    participant API as Flask API
    participant Worker as PCAP Worker
    participant ML as ML Models
    participant IPS as IPS Engine
    participant Log as Logger
    participant Storage as Storage
    
    User->>Web: Upload PCAP
    Web->>API: POST /api/upload_pcap
    API->>Storage: Save to incoming/
    API-->>Web: ✓ Uploaded
    
    Note over Worker: Poll loop
    Worker->>Storage: Check incoming/
    Worker->>Worker: Found: file.pcap
    
    Worker->>Worker: Convert PCAP → CSV<br/>nprobe
    Worker->>Worker: Load df_raw (N flows)
    
    loop For each of 6 models
        Worker->>ML: get_model(name, task)
        ML-->>Worker: model, scaler
        Worker->>Worker: predict_vector()
        Worker->>Worker: votes += result
    end
    
    Worker->>IPS: hybrid_detection()
    IPS->>IPS: For each flow:<br/>check JA3/JA3S/SNI
    IPS-->>Worker: final_decisions[], sources[]
    
    Worker->>Log: update_consensus_log()
    Worker->>Log: update_ips_log()
    Worker->>Log: update_model_log() x6
    
    Log->>Storage: Write CSV logs
    
    Worker->>Storage: is_threat?
    alt Has Threat
        Worker->>Storage: Move to evidence/
    else Safe
        Worker->>Storage: Delete PCAP
    end
    
    Worker->>Worker: Update FILE_STATUS
    Note over Web: Frontend polls
    Web->>API: GET /api/status
    API-->>Web: Updated dashboard
```

---

## 10. SYSTEM CONFIGURATION STATE

```mermaid
stateDiagram-v2
    [*] --> Startup
    
    Startup --> LoadConfig: init_db_data()
    LoadConfig --> InMemory: SYSTEM_CONFIG loaded
    
    InMemory --> DetectionMode: Mode selection
    InMemory --> VotingThreshold: Threshold 1-6
    InMemory --> IPSEnabled: IPS toggle
    
    DetectionMode --> VotingMode: "voting"
    DetectionMode --> RFOnlyMode: "rf_only"
    
    VotingMode --> Analysis6Models: 6 models vote
    RFOnlyMode --> AnalysisRFOnly: 1 model fast
    
    Analysis6Models --> HybridDetection
    AnalysisRFOnly --> HybridDetection
    
    IPSEnabled --> HPCheck: Check TLS FP
    IPSEnabled --> NoIPSCheck: Skip IPS
    
    HPCheck --> HybridDetection
    NoIPSCheck --> HybridDetection
    
    HybridDetection --> FinalDecision
    FinalDecision --> Logging
    Logging --> [*]
    
    note right of VotingThreshold
        Higher = Conservative
        Lower = Sensitive
    end note
```


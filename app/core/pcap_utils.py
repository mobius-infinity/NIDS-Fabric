import os
import subprocess
import pandas as pd
from flask import current_app

# Danh sách Feature cần thiết cho nprobe (giống file gốc)
LIGHTGBM_23_FEATURES = [
    '%PROTOCOL', '%L7_PROTO', '%IN_PKTS', '%OUT_PKTS', '%FLOW_DURATION_MILLISECONDS',
    '%SERVER_TCP_FLAGS', '%DURATION_OUT', '%MIN_TTL', '%MAX_TTL', '%MAX_IP_PKT_LEN',
    '%RETRANSMITTED_IN_BYTES', '%SRC_TO_DST_AVG_THROUGHPUT', '%DST_TO_SRC_AVG_THROUGHPUT',
    '%NUM_PKTS_UP_TO_128_BYTES', '%NUM_PKTS_128_TO_256_BYTES', '%NUM_PKTS_256_TO_512_BYTES',
    '%NUM_PKTS_512_TO_1024_BYTES', '%NUM_PKTS_1024_TO_1514_BYTES', '%TCP_WIN_MAX_OUT',
    '%ICMP_IPV4_TYPE', '%DNS_QUERY_ID', '%DNS_QUERY_TYPE', '%FTP_COMMAND_RET_CODE'
]

DISPLAY_FEATURES = ['%IPV4_SRC_ADDR', '%IPV4_DST_ADDR', '%L4_SRC_PORT', '%L4_DST_PORT', '%FIRST_SWITCHED', '%LAST_SWITCHED']

# Feature list cho DNN và Random Forest (bỏ dấu %)
FEATURES_DNN_RF = [f[1:] for f in LIGHTGBM_23_FEATURES]

def convert_pcap_to_csv(pcap_path, dump_dir):
    """
    Sử dụng nprobe để trích xuất feature từ PCAP ra CSV.
    """
    nprobe_path = current_app.config['NPROBE_PATH']
    
    # Tạo chuỗi template cho nprobe
    full_feature_list = LIGHTGBM_23_FEATURES + DISPLAY_FEATURES
    template_str = "".join([f.strip() for f in full_feature_list])
    
    if not os.path.exists(nprobe_path):
        print(f"[Error] nprobe not found at {nprobe_path}")
        return None

    abs_dump = os.path.abspath(dump_dir)
    os.makedirs(abs_dump, exist_ok=True)
    
    cmd = [
        nprobe_path, 
        "-i", os.path.abspath(pcap_path), 
        "-V", "9", 
        "-n", "none", 
        "-T", template_str, 
        "--dump-path", abs_dump, 
        "--dump-format", "t", 
        "--csv-separator", ",", 
        "--dont-reforge-timestamps"
    ]
    
    try:
        # Chạy lệnh với timeout 600s
        subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600)
        
        # Tìm các file csv được tạo ra
        found_files = [
            os.path.join(r, f) 
            for r, d, fs in os.walk(abs_dump) 
            for f in fs 
            if os.path.getsize(os.path.join(r, f)) > 0
        ]
        
        if not found_files:
            return None
            
        # Gộp các file CSV lại (nếu nprobe tạo nhiều file)
        final_df = pd.concat(
            [pd.read_csv(f, sep=',', on_bad_lines='skip') for f in found_files], 
            ignore_index=True
        )
        
        out_path = os.path.join(dump_dir, "processed.csv")
        final_df.to_csv(out_path, index=False)
        return out_path
        
    except Exception as e:
        print(f"[PCAP Error] {e}")
        return None

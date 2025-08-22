import streamlit as st
import pandas as pd
import subprocess
import os
import json
import time

st.set_page_config(page_title="Network Sniffer Live Demo")
st.title("🌐 Network Packet Sniffer (Resume Demo)")
st.write("Live packet capture demo using Python and Scapy")

# Path to sniffer subprocess
sniffer_script = os.path.join(os.path.dirname(__file__), "sniffer.py")
log_file = os.path.join(os.path.dirname(__file__), "packets_log.json")

# Session state for subprocess
if "sniffer_proc" not in st.session_state:
    st.session_state.sniffer_proc = None
if "filter_proto" not in st.session_state:
    st.session_state.filter_proto = "All"

# ------------------------
# UI Buttons
# ------------------------
iface = st.text_input("Network Interface:", "eth0")

col1, col2 = st.columns(2)
with col1:
    if st.button("Start Sniffer") and st.session_state.sniffer_proc is None:
        # Start subprocess
        st.session_state.sniffer_proc = subprocess.Popen(
            ["python3", sniffer_script, iface]
        )
        st.success(f"Sniffer started on {iface}!")

with col2:
    if st.button("Stop Sniffer") and st.session_state.sniffer_proc is not None:
        st.session_state.sniffer_proc.terminate()
        st.session_state.sniffer_proc = None
        st.warning("Sniffer stopped!")

# Protocol filter
filter_proto = st.selectbox("Protocol Filter", ["All", "TCP", "UDP", "ICMP"])

# ------------------------
# Live table display
# ------------------------
table_container = st.empty()
stats_container = st.empty()

if st.session_state.sniffer_proc is not None:
    for _ in range(1000):  # Run live update loop
        if os.path.exists(log_file):
            with open(log_file, "r") as f:
                try:
                    packets = json.load(f)
                except:
                    packets = []

            # Apply filter
            if filter_proto != "All":
                packets = [p for p in packets if p["Protocol"] == filter_proto]

            # Update table
            if packets:
                df = pd.DataFrame(packets)
                table_container.dataframe(df)

                # Stats
                total = len(packets)
                tcp_count = len([p for p in packets if p["Protocol"] == "TCP"])
                udp_count = len([p for p in packets if p["Protocol"] == "UDP"])
                icmp_count = len([p for p in packets if p["Protocol"] == "ICMP"])
                stats_container.markdown(
                    f"**Total:** {total} | **TCP:** {tcp_count} | **UDP:** {udp_count} | **ICMP:** {icmp_count}"
                )
        time.sleep(1)

# Show final captured packets after stopping
if os.path.exists(log_file):
    with open(log_file, "r") as f:
        try:
            packets = json.load(f)
        except:
            packets = []

    if packets:
        st.subheader("Captured Packets Output")
        st.dataframe(pd.DataFrame(packets))

import streamlit as st
import pandas as pd
import json
import os
import time

st.set_page_config(page_title="Network Sniffer Demo")
st.title("🌐 Network Packet Sniffer Demo")
st.write("**This is a demo version with pre-recorded packets for safe online deployment.**")

# ------------------------
# Load pre-recorded packets
# ------------------------
demo_file = os.path.join(os.path.dirname(__file__), "packets_demo.json")
with open(demo_file, "r") as f:
    packets_list = json.load(f)

# ------------------------
# Session state
# ------------------------
if "running" not in st.session_state:
    st.session_state.running = False
if "displayed_packets" not in st.session_state:
    st.session_state.displayed_packets = []

# ------------------------
# Buttons
# ------------------------
col1, col2 = st.columns(2)
with col1:
    if st.button("Start Simulation") and not st.session_state.running:
        st.session_state.running = True
        st.session_state.displayed_packets = []

with col2:
    if st.button("Stop Simulation") and st.session_state.running:
        st.session_state.running = False

# ------------------------
# Protocol filter
# ------------------------
filter_proto = st.selectbox("Protocol Filter", ["All", "TCP", "UDP", "ICMP"])

# ------------------------
# Table and stats containers
# ------------------------
table_container = st.empty()
stats_container = st.empty()

# ------------------------
# Simulation loop
# ------------------------
if st.session_state.running:
    for pkt in packets_list:
        st.session_state.displayed_packets.append(pkt)

        # Apply filter
        if filter_proto != "All":
            filtered = [p for p in st.session_state.displayed_packets if p["Protocol"] == filter_proto]
        else:
            filtered = st.session_state.displayed_packets.copy()

        # Color-coded display
        df = pd.DataFrame(filtered)
        df_styled = df.style.applymap(
            lambda x: "color: green;" if x == "TCP" else
                      "color: orange;" if x == "UDP" else
                      "color: blue;" if x == "ICMP" else "color: black;",
            subset=["Protocol"]
        )
        table_container.dataframe(df_styled)

        # Stats
        total = len(filtered)
        tcp_count = len([p for p in filtered if p["Protocol"] == "TCP"])
        udp_count = len([p for p in filtered if p["Protocol"] == "UDP"])
        icmp_count = len([p for p in filtered if p["Protocol"] == "ICMP"])
        stats_container.markdown(
            f"**Total:** {total} | **TCP:** {tcp_count} | **UDP:** {udp_count} | **ICMP:** {icmp_count}"
        )

        time.sleep(0.2)

# ------------------------
# Show final captured packets after stopping
# ------------------------
if not st.session_state.running and st.session_state.displayed_packets:
    st.subheader("Captured Packets Output")
    if filter_proto != "All":
        final_filtered = [p for p in st.session_state.displayed_packets if p["Protocol"] == filter_proto]
    else:
        final_filtered = st.session_state.displayed_packets.copy()
    df_final = pd.DataFrame(final_filtered)
    st.dataframe(df_final)

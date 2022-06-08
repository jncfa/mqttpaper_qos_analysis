#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''MQTT Packet analysis script developed for the experiments ran in ISR.

This script automatically performs the RTT and Packet Loss analysis of the packets given the folder containing
all Wireshark capture files ('.pcap'). 

It uses pyshark (Python wrapper for the tshark tool) to analyze the packets.

Setting up:
    Use the supplied Dockerfile to setup a development environment, or manually install all dependencies.
    Make sure to mount the folder with the log files in /logs/.
'''

from collections import deque
from datetime import datetime
import pyshark
import pandas as pd
import numpy as np

#import nest_asyncio
#nest_asyncio.apply()

# Define all experiment variables
CLIENT_LIST = [
    '10.231.219.206', '10.231.219.81', '10.231.219.73', '10.231.219.185'
]
HOST_IP = '10.231.201.175'

FREQUENCY_LIST = [1, 10, 100]
PACKET_SIZES = ['small', 'medium', 'large']
QOS_LEVELS = [0, 1, 2]

# Mapping to get real packet size
PACKET_SIZE_BYTES = {'small': 1250, 'medium': 12500, 'large': 125000}

# Headers to be used in pandas.DataFrame
FREQUENCY_HEADER = 'FREQUENCY'
PACKET_SIZE_HEADER = 'PACKET_SIZE'
NUM_CLIENTS_HEADER = 'NUM_CLIENTS'
QOS_LEVEL_HEADER = 'QOS_LEVEL'

RTT_HEADER = 'RTT'
RTT_MEAN_HEADER = 'RTT Mean'
RTT_MEDIAN_HEADER = 'RTT Median'
RTT_STD_HEADER = 'RTT Std'
PACKET_LOSS_HEADER = 'Packet Loss'

# Headers to be used in packet_raw_info
TCP_SEGMENTS_HEADER = "tcp.segment"  # segments that composed the packet
TCP_FIRST_SEGMENT_HEADER = TCP_SEGMENTS_HEADER  # first segment that composed the packet
TCP_FIRST_SEGMENT_TIMESTAMP_HEADER = "tcp.segments.timestamp"  # first segment that composed the packet

MQTT_MSGID_HEADER = "mqtt.msgid"  # id of the MQTT message, used to follow up on QoS on MQTT level
MQTT_MSGLEN_HEADER = "mqtt.msglen"  # full length of the packet (payload + overhead)
FRAME_NUMBER_HEADER = "frame.number"  # number of the frame
FRAME_TIMESTAMP_HEADER = "frame.time"  # timestamp of the recorded packet
IP_ADDR_HEADER = "ip.addr"

MQTT_PACKET_ACKED_HEADER = "MQTT_PACKET_ACKED"  # indicates if the packed was acked or not
MQTT_PACKET_ACK_TIMESTAMP_HEADER = "MQTT_PACKET_ACK_TIMESTAMP"  # timestamp of packet ack (PUBACK for QoS1, PUBCOMP for QoS2)

# Useful functions
# Packet file name format
FILENAME_FMT = '/logs/f{}c{}qos{}{}.pcap'

def get_log_filename(frequency, number_of_clients, qos_level, packet_size):
    return FILENAME_FMT.format(frequency, number_of_clients, qos_level,
                               packet_size)


# Get Client IP from ip.addr info
getClientIP = lambda addr: addr[0] if addr[0] != HOST_IP else addr[1]


# Create double FileCapture from capture file and display filter
def create_file_capture(capture_filename, display_filter):
    return pyshark.FileCapture(capture_filename,
                               use_json=False,
                               keep_packets=False,
                               display_filter=display_filter)  #, debug=True)


# Wireshark display filters
TSHARK_DF_AND = "&&"
TSHARK_DF_OR = "||"

# Template filter for different IPs
TSHARK_DF_IPFILTER_FMT = "ip.addr == {}"
TSHARK_DF_IPFILTER_SRC_FMT = "ip.src_host == {}"
TSHARK_DF_IPFILTER_DST_FMT = "ip.dst_host == {}"
TSHARK_DF_IPFILTER = lambda ip: TSHARK_DF_IPFILTER_FMT.format(ip)
TSHARK_DF_IPFILTER_SRC = lambda ip: TSHARK_DF_IPFILTER_SRC_FMT.format(ip)
TSHARK_DF_IPFILTER_DST = lambda ip: TSHARK_DF_IPFILTER_DST_FMT.format(ip)

# Filters for different MQTT packets
MQTT_PUBLISH_MSGTYPE = 3
MQTT_PUBACK_MSGTYPE = 4
MQTT_PUBCOMP_MSGTYPE = 7

TSHARK_DF_MQTTPUBLISH = f"mqtt.msgtype == {MQTT_PUBLISH_MSGTYPE}"
TSHARK_DF_MQTTPUBACK = f"mqtt.msgtype == {MQTT_PUBACK_MSGTYPE}"
TSHARK_DF_MQTTPUBCOMP = f"mqtt.msgtype == {MQTT_PUBCOMP_MSGTYPE}"

# Filters the 1883 port so we only get MQTT packets
TSHARK_DF_MQTT_TCPFILTER = "tcp.port == 1883"

# Filter for ACK packets and their corresponding ACK'd frame
TSHARK_DF_ACKS_FRAME_FMT = "tcp.analysis.acks_frame >= {}"
TSHARK_DF_ACKS_FRAME = lambda number: TSHARK_DF_ACKS_FRAME_FMT.format(number)

# pyshark doesn't provide any easy way to access the data, so we need to do this to get it
TSHARK_DF_START_ON_FRAME_FMT = "frame.number > {}"
TSHARK_DF_START_ON_FRAME = lambda number: TSHARK_DF_START_ON_FRAME_FMT.format(
    number)
TSHARK_DF_GET_FRAME_FMT = "frame.number == {}"
TSHARK_DF_GET_FRAME = lambda number: TSHARK_DF_GET_FRAME_FMT.format(number)

# Log files are processed in two-passes:
# - First pass scans for MQTT packets and gets their info (segment numbers for MQTT PUBLISH, etc)
# - Second pass processes the underlying TCP fragments and ACKs and updates the previous info with timestamps when needed
def process_logfile(frequency, number_of_clients, qos_level, packet_size):
    capture_filename = get_log_filename(frequency, number_of_clients,
                                        qos_level, packet_size)
    packet_info = []

    # print filename so we get some verbosity in the console
    print(capture_filename)

    # split capture according to QoS level
    if qos_level == 0:
        # dict of all MQTT publish packets: map from {frame.number -> packet_data}
        mqttpub_packet_list = {}

        # create file capture to parse only MQTT packets
        mqtt_capture = create_file_capture(capture_filename,
                                           TSHARK_DF_MQTTPUBLISH)

        for packet in mqtt_capture:
            # check for multiple MQTT layers
            for mqtt_layer in packet.get_multiple_layers("mqtt"):
                if int(mqtt_layer.msgtype) == MQTT_PUBLISH_MSGTYPE:
                    # get packet data
                    packet_data = {
                        IP_ADDR_HEADER: [packet.ip.src, packet.ip.dst],
                        FRAME_TIMESTAMP_HEADER: float(packet.frame_info.time_epoch),
                        FRAME_NUMBER_HEADER: int(packet.frame_info.number),
                        TCP_FIRST_SEGMENT_HEADER: int(packet.data.tcp_segment if ("data" in packet) else packet.frame_info.number),
                        MQTT_MSGLEN_HEADER: int(packet.mqtt.len),
                        TCP_FIRST_SEGMENT_TIMESTAMP_HEADER: float(packet.frame_info.time_epoch) if not ("data" in packet) else None,
                    }
                    mqttpub_packet_list[packet_data[TCP_FIRST_SEGMENT_HEADER]] = packet_data

        # close subprocess
        mqtt_capture.close()

        # create a queue so we can ACK the packets in order
        # queues are created per client to validate the ACKs properly
        mqttpub_packet_deque = {
            client: deque(
                sorted(filter(
                    lambda packet: client == getClientIP(packet[IP_ADDR_HEADER]),
                    mqttpub_packet_list.values()),
                       key=(lambda packet: -packet[FRAME_NUMBER_HEADER])))
            for client in CLIENT_LIST
        }

        # grab last packet of each client
        last_packet_to_ack = {
            client: mqttpub_packet_deque[client].pop()
            for client in mqttpub_packet_deque if len(mqttpub_packet_deque[client]) > 0
        }

        # check all TCP packets captured
        tcp_capture = create_file_capture(capture_filename,
                                          TSHARK_DF_MQTT_TCPFILTER)
        for packet in tcp_capture:
            if packet.ip.dst == HOST_IP:
                # check if it's an ACK packet from the client
                if "analysis_acks_frame" in packet.tcp.field_names:
                    # check if there's a packet that is missing an ACK
                    if last_packet_to_ack.get(packet.ip.src) is not None:
                        # check if it ACKs the client's last PUBLISH
                        if (int(packet.tcp.analysis_acks_frame) >=
                                last_packet_to_ack.get(packet.ip.src)[FRAME_NUMBER_HEADER]):
                            # add packet to the list
                            packet_info.append({
                                FREQUENCY_HEADER: frequency,
                                MQTT_MSGLEN_HEADER: last_packet_to_ack.get(packet.ip.src)[MQTT_MSGLEN_HEADER],
                                PACKET_SIZE_HEADER: PACKET_SIZE_BYTES[packet_size],
                                NUM_CLIENTS_HEADER: number_of_clients,
                                QOS_LEVEL_HEADER: qos_level,
                                RTT_HEADER: (float(packet.frame_info.time_epoch) -
                                mqttpub_packet_list[last_packet_to_ack.get(packet.ip.src)[TCP_FIRST_SEGMENT_HEADER]][TCP_FIRST_SEGMENT_TIMESTAMP_HEADER])
                            })
                            # update last packet ACK'd
                            last_packet_to_ack[
                                packet.ip.src] = mqttpub_packet_deque[
                                    packet.ip.src].pop() if len(
                                        mqttpub_packet_deque[
                                            packet.ip.src]) > 0 else None
            else:
                # check if the current packet is one of the first segments, if not then skip
                if mqttpub_packet_list.get(int(packet.frame_info.number)) is not None:
                    mqttpub_packet_list[int(packet.frame_info.number)][TCP_FIRST_SEGMENT_TIMESTAMP_HEADER] = float(
                        packet.frame_info.time_epoch)

        # close file capture
        tcp_capture.close()
    else:
        # dict of all MQTT publish packets: map from {packet.ip.addr -> packet_data}
        mqttpub_packet_list = {}

        # create file capture to parse only MQTT packets
        mqtt_capture = create_file_capture(
            capture_filename,
            display_filter=((TSHARK_DF_MQTTPUBLISH + TSHARK_DF_OR +
                             TSHARK_DF_MQTTPUBACK) if (qos_level == 1) else
                            (TSHARK_DF_MQTTPUBLISH + TSHARK_DF_OR +
                             TSHARK_DF_MQTTPUBCOMP)))

        for packet in mqtt_capture:
            packet_ip_addrs = [packet.ip.src, packet.ip.dst]
            # check for multiple MQTT layers
            for mqtt_layer in packet.get_multiple_layers("mqtt"):
                # skip malformed packets / fragments
                if "msgid" in mqtt_layer.field_names:
                    # check if it's a MQTT PUBLISH
                    if int(mqtt_layer.msgtype) == MQTT_PUBLISH_MSGTYPE:
                        packet_data = {
                            IP_ADDR_HEADER: packet_ip_addrs,
                            FRAME_TIMESTAMP_HEADER: float(packet.frame_info.time_epoch),
                            FRAME_NUMBER_HEADER: int(packet.frame_info.number),
                            TCP_FIRST_SEGMENT_HEADER: int(packet.data.tcp_segment if ("data" in packet) else packet.frame_info.number),
                            MQTT_MSGLEN_HEADER: int(packet.mqtt.len),
                            TCP_FIRST_SEGMENT_TIMESTAMP_HEADER: float(packet.frame_info.time_epoch) if not ("data" in packet) else None,
                            MQTT_PACKET_ACK_TIMESTAMP_HEADER: None,
                            MQTT_PACKET_ACKED_HEADER: False,
                        }
                        mqttpub_packet_list[(frozenset(packet_ip_addrs), int(packet.mqtt.msgid))] = packet_data
                    #check if it's a PUBACK / PUBCOMP
                    elif (int(mqtt_layer.msgtype) == MQTT_PUBACK_MSGTYPE or int(mqtt_layer.msgtype) == MQTT_PUBCOMP_MSGTYPE):
                        # get saved packet
                        mqtt_packet = mqttpub_packet_list.get((frozenset(packet_ip_addrs), int(mqtt_layer.msgid)))
                        if mqtt_packet is not None:
                            mqttpub_packet_list[(frozenset(packet_ip_addrs), int(mqtt_layer.msgid))][MQTT_PACKET_ACK_TIMESTAMP_HEADER] = float(packet.frame_info.time_epoch)
                            mqttpub_packet_list[(frozenset(packet_ip_addrs), int(mqtt_layer.msgid))][MQTT_PACKET_ACKED_HEADER] = True

        # close subprocess
        mqtt_capture.close()

        # reshape dict to be indexed by first segment frame number
        mqttpub_packet_list = {
            packet[TCP_FIRST_SEGMENT_HEADER]: packet
            for packet in mqttpub_packet_list.values()
            if packet[MQTT_PACKET_ACKED_HEADER]
        }

        # check all TCP packets sent by the broker to fetch the first fragments sent per MQTT packet
        tcp_capture = create_file_capture(
            capture_filename, TSHARK_DF_MQTT_TCPFILTER + TSHARK_DF_AND +
            TSHARK_DF_IPFILTER_SRC(HOST_IP))
        for packet in tcp_capture:
            # check if the current packet is one of the first segments, if not then skip
            if mqttpub_packet_list.get(int(packet.frame_info.number)) is not None:
                packet_info.append({
                    FREQUENCY_HEADER: frequency,
                    MQTT_MSGLEN_HEADER: mqttpub_packet_list[int(packet.frame_info.number)][MQTT_MSGLEN_HEADER],
                    PACKET_SIZE_HEADER: PACKET_SIZE_BYTES[packet_size],
                    NUM_CLIENTS_HEADER: number_of_clients,
                    QOS_LEVEL_HEADER: qos_level,
                    RTT_HEADER: mqttpub_packet_list[int(packet.frame_info.number)][MQTT_PACKET_ACK_TIMESTAMP_HEADER] - float(packet.frame_info.time_epoch)
                })
        # close file capture
        tcp_capture.close()
    return packet_info


# list placeholder (to concat the info faster and convert it to a DataFrame in the end)
mqttpacket_raw_info = []

try:
    # loop through all logs
    for freq in FREQUENCY_LIST:
        for num_clients in range(1, len(CLIENT_LIST) + 1):
            for qos in QOS_LEVELS:
                for packet_len in PACKET_SIZES:
                    try:
                        mqttpacket_raw_info = mqttpacket_raw_info + process_logfile(
                            freq, num_clients, qos, packet_len)
                    except (FileNotFoundError) as e:
                        print(e)  # report instances of failed / broken logs :)
                    except Exception as e:
                        print(e)

except KeyboardInterrupt as e:
    # save data before raising exception
    print("Manual interrupt")
    mqttpacket_raw_info = pd.DataFrame(mqttpacket_raw_info).to_csv(
        datetime.now().strftime("%d-%m-%Y_%H_%M_%S") + "-backup_crisis_ki.csv")
    raise e
except Exception as e:
    # save data before raising exception
    mqttpacket_raw_info = pd.DataFrame(mqttpacket_raw_info).to_csv(
        datetime.now().strftime("%d-%m-%Y_%H_%M_%S") + "-backup_crisis.csv")
    raise e

# convert to a DataFrame for easy analysis
mqttpacket_raw_info = pd.DataFrame(mqttpacket_raw_info)
mqttpacket_raw_info.to_csv("raw_data_tests.csv")

# group data by dependent variables
mqttpacket_raw_info_groups = mqttpacket_raw_info.groupby(by=[
    FREQUENCY_HEADER, NUM_CLIENTS_HEADER, PACKET_SIZE_HEADER, QOS_LEVEL_HEADER
])

# Get RTT mean and STD
mqttpacket_info = mqttpacket_raw_info_groups.agg(
    **{
        RTT_MEAN_HEADER: pd.NamedAgg(column=RTT_HEADER, aggfunc=np.mean),
        RTT_STD_HEADER: pd.NamedAgg(column=RTT_HEADER, aggfunc=np.std),
        RTT_MEDIAN_HEADER: pd.NamedAgg(column=RTT_HEADER, aggfunc=np.median),
    })

# Grab nº of packets sent & reset
mqttpacket_info[PACKET_LOSS_HEADER] = mqttpacket_raw_info_groups.size()
mqttpacket_info.reset_index(inplace=True)

# Calculate the nº of packets sent and fix the value when more than 1000 packets per client are sent
mqttpacket_info[PACKET_LOSS_HEADER] = (
    1 - (mqttpacket_info[PACKET_LOSS_HEADER] /
         (1000 * mqttpacket_info[NUM_CLIENTS_HEADER]))) * 100

mqttpacket_info.loc[mqttpacket_info[PACKET_LOSS_HEADER] < 0, [PACKET_LOSS_HEADER,]] = 0
mqttpacket_info.to_csv("analyzed_data.csv")

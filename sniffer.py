import scapy.all as sc
from collections import defaultdict
import math
import joblib
import csv

class Sniffer:
    
    def __init__(self):
        self.flows = defaultdict(lambda: {
            'total_length': 0, 
            'packet_count': 0, 
            'packet_lengths': [], 
            'fwd_total_length': 0, 
            'bwd_total_length': 0,
            'fwd_packet_count': 0,
            'bwd_packet_count': 0,
            'fwd_packet_lengths': [],
            'bwd_packet_lengths': [],
            'fwd_header_length': 0,
            'subflows': defaultdict(lambda: {'fwd_total_length': 0, 'bwd_total_length': 0}),
            'init_win_bytes_fwd': None,
            'fwd_packet_length_max': 0,
            'arrival_times': [],
            'flow_iat_max': 0,
            'dst_port': None,
            'start_time': None,
            'end_time': None,
            'fwd_timestamps': [],
            'fwd_segment_size': 0,
            'fwd_iat_total': 0, 
            'fwd_iat_mean': 0,
            'fwd_packets_per_second': 0, 
            'bwd_segment_size': 0,

        })
        self.scaler = joblib.load('data/minmax_scaler2.joblib')
        self.pca = joblib.load('data/pca_model2.joblib')
        self.random_forest_model = joblib.load('data/random_forest_model2.joblib')
        

    def update_flow(self, packet):
        # Extract IP layer information
        ip_layer = packet[sc.IP]
        src = ip_layer.src
        dst = ip_layer.dst
        flow_id = (src, dst)
        timestamp = packet.time 

        # Determine the direction of the packet
        if (src, dst) not in self.flows and (dst, src) in self.flows:
            flow_id = (dst, src)
            direction = 'bwd'
        else:
            direction = 'fwd'

        if self.flows[flow_id]['start_time'] is None:
            self.flows[flow_id]['start_time'] = timestamp

        self.flows[flow_id]['end_time'] = timestamp

        # Update flow data
        self.flows[flow_id]['total_length'] += len(packet)
        self.flows[flow_id]['packet_count'] += 1
        self.flows[flow_id]['packet_lengths'].append(len(packet))
        self.flows[flow_id]['arrival_times'].append(timestamp) 

        if packet.haslayer(sc.TCP):
            self.flows[flow_id]['dst_port'] = packet[sc.TCP].dport
        elif packet.haslayer(sc.UDP):
            self.flows[flow_id]['dst_port'] = packet[sc.UDP].dport

        if direction == 'fwd':
            self.flows[flow_id]['fwd_total_length'] += len(packet)
            self.flows[flow_id]['fwd_packet_count'] += 1
            self.flows[flow_id]['fwd_packet_lengths'].append(len(packet))
            if self.flows[flow_id]['fwd_timestamps']:
                fwd_iat = packet.time - self.flows[flow_id]['fwd_timestamps'][-1]
                self.flows[flow_id]['fwd_iat_total'] += fwd_iat
                self.flows[flow_id]['fwd_iat_mean'] = self.flows[flow_id]['fwd_iat_total'] / len(self.flows[flow_id]['fwd_timestamps'])
            
            self.flows[flow_id]['fwd_timestamps'].append(packet.time)

            if self.flows[flow_id]['start_time'] is not None:
                flow_duration = packet.time - self.flows[flow_id]['start_time']
                if flow_duration > 0:
                    self.flows[flow_id]['fwd_packets_per_second'] = self.flows[flow_id]['fwd_packet_count'] / flow_duration

            # Track subflow
            subflow_id = ip_layer.dport
            self.flows[flow_id]['subflows'][subflow_id]['fwd_total_length'] += len(packet)
            self.update_init_win_bytes_fwd(packet, flow_id)
            if len(packet) > self.flows[flow_id]['fwd_packet_length_max']:
                self.flows[flow_id]['fwd_packet_length_max'] = len(packet)
            if packet.haslayer(sc.TCP):
                self.flows[flow_id]['fwd_header_length'] += len(packet[sc.IP]) + len(packet[sc.TCP])
            elif packet.haslayer(sc.UDP):
                self.flows[flow_id]['fwd_header_length'] += len(packet[sc.IP]) + len(packet[sc.UDP])
        else:
            self.flows[flow_id]['bwd_total_length'] += len(packet)
            self.flows[flow_id]['bwd_packet_count'] += 1
            self.flows[flow_id]['bwd_packet_lengths'].append(len(packet))
            if self.flows[flow_id]['bwd_packet_count'] > 0:
                self.flows[flow_id]['bwd_segment_size'] = (
                self.flows[flow_id]['bwd_total_length'] / self.flows[flow_id]['bwd_packet_count'])

            # Track subflow
            subflow_id = ip_layer.dport
            self.flows[flow_id]['subflows'][subflow_id]['bwd_total_length'] += len(packet)

        if len(self.flows[flow_id]['arrival_times']) > 1:
            iat_times = [j - i for i, j in zip(self.flows[flow_id]['arrival_times'][:-1], self.flows[flow_id]['arrival_times'][1:])]
            self.flows[flow_id]['flow_iat_max'] = max(iat_times)

        self.calculate_avg_fwd_segment_size(flow_id)

    def average_packet_size_function(self, flow_id):
        packet_count = self.flows[flow_id]['packet_count']
        if packet_count == 0:
            return 0.0
        total_length = self.flows[flow_id]['total_length']
        avg_packet_size = total_length / packet_count
        return avg_packet_size

    def packet_length_std_function(self, flow_id):
        packet_lengths = self.flows[flow_id]['packet_lengths']
        packet_count = self.flows[flow_id]['packet_count']
        
        # If there's only one packet, the standard deviation is 0
        if packet_count <= 1:
            return 0.0
        
        # Calculate the mean packet length
        mean_length = sum(packet_lengths) / packet_count
        # Calculate the variance
        variance = sum((length - mean_length) ** 2 for length in packet_lengths) / packet_count
        # Calculate the standard deviation
        std_dev = math.sqrt(variance)
        return std_dev

    def packet_length_variance_function(self, flow_id):
        packet_lengths = self.flows[flow_id]['packet_lengths']
        packet_count = self.flows[flow_id]['packet_count']
        
        # If there's only one packet, the variance is 0
        if packet_count <= 1:
            return 0.0
        
        # Calculate the mean packet length
        mean_length = sum(packet_lengths) / packet_count
        # Calculate the variance
        variance = sum((length - mean_length) ** 2 for length in packet_lengths) / packet_count
        return variance

    def total_bwd_packet_length_function(self, flow_id):
        return self.flows[flow_id]['bwd_total_length']

    def subflow_bwd_bytes_function(self, flow_id, subflow_id):
        return self.flows[flow_id]['subflows'][subflow_id]['bwd_total_length']

    def avg_bwd_segment_size_function(self, flow_id):
        bwd_packet_count = self.flows[flow_id]['bwd_packet_count']
        if bwd_packet_count == 0:
            return 0.0
        bwd_total_length = self.flows[flow_id]['bwd_total_length']
        avg_bwd_segment_size = bwd_total_length / bwd_packet_count
        return avg_bwd_segment_size

    def bwd_packet_length_mean_function(self, flow_id):
        bwd_packet_count = self.flows[flow_id]['bwd_packet_count']
        if bwd_packet_count == 0:
            return 0.0
        bwd_total_length = self.flows[flow_id]['bwd_total_length']
        bwd_packet_length_mean = bwd_total_length / bwd_packet_count
        return bwd_packet_length_mean

    def total_fwd_packet_length_function(self, flow_id):
        return self.flows[flow_id]['fwd_total_length']

    def subflow_fwd_bytes_function(self, flow_id, subflow_id):
        return self.flows[flow_id]['subflows'][subflow_id]['fwd_total_length']

    def bwd_packet_length_max_function(self, flow_id):
        bwd_packet_lengths = self.flows[flow_id]['bwd_packet_lengths']
        if not bwd_packet_lengths:
            return 0
        return max(bwd_packet_lengths)

    def max_packet_length_function(self, flow_id):
        packet_lengths = self.flows[flow_id]['packet_lengths']
        if not packet_lengths:
            return 0
        return max(packet_lengths)

    def update_init_win_bytes_fwd(self, packet, flow_id):
        if packet.haslayer(sc.TCP):
            if self.flows[flow_id]['init_win_bytes_fwd'] is None:
                self.flows[flow_id]['init_win_bytes_fwd'] = packet[sc.TCP].window

    def init_win_bytes_fwd_function(self, flow_id):
        return self.flows[flow_id]['init_win_bytes_fwd'] if self.flows[flow_id]['init_win_bytes_fwd'] is not None else 0

    def fwd_packet_length_max_function(self, flow_id):
        return self.flows[flow_id]['fwd_packet_length_max']

    def flow_iat_max_function(self, flow_id):
        return self.flows[flow_id]['flow_iat_max']

    def destination_port_function(self, flow_id):
        return self.flows[flow_id].get('dst_port', 0)

    def flow_duration_function(self, flow_id):
        start_time = self.flows[flow_id]['start_time']
        end_time = self.flows[flow_id]['end_time']
        if start_time is None or end_time is None:
            return 0.0
        return end_time - start_time

    def flow_bytes_per_second_function(self, flow_id):
        total_length = self.flows[flow_id]['total_length']
        flow_duration = self.flow_duration_function(flow_id)
        if flow_duration == 0:
            return 0.0
        return total_length / flow_duration

    def fwd_iat_max_function(self, flow_id):
        fwd_timestamps = self.flows[flow_id]['fwd_timestamps']
        if len(fwd_timestamps) < 2:
            return 0.0

        fwd_iats = [t2 - t1 for t1, t2 in zip(fwd_timestamps[:-1], fwd_timestamps[1:])]
        return max(fwd_iats)

    def fwd_packet_length_mean_function(self, flow_id):
        fwd_packet_lengths = self.flows[flow_id]['fwd_packet_lengths']
        fwd_packet_count = self.flows[flow_id]['fwd_packet_count']
    
        if fwd_packet_count == 0:
            return 0.0
    
        fwd_packet_length_mean = sum(fwd_packet_lengths) / fwd_packet_count
        return fwd_packet_length_mean

    def fwd_header_length_function(self, flow_id):
        return self.flows[flow_id]['fwd_header_length']

    def calculate_avg_fwd_segment_size(self, flow_id):
        fwd_packet_count = self.flows[flow_id]['fwd_packet_count']
        if fwd_packet_count == 0:
            self.flows[flow_id]['fwd_segment_size'] = 0.0
        else:
            self.flows[flow_id]['fwd_segment_size'] = self.flows[flow_id]['fwd_total_length'] / fwd_packet_count

    def fwd_iat_total_function(self, flow_id):
        return self.flows[flow_id]['fwd_iat_total']

    def fwd_iat_mean_function(self, flow_id):
        return self.flows[flow_id]['fwd_iat_mean']

    def fwd_packets_per_second_function(self, flow_id):
        return self.flows[flow_id]['fwd_packets_per_second']

    def avg_bwd_segment_size_function(self, flow_id):
        return self.flows[flow_id]['bwd_segment_size']

    def save_features_to_csv(self, features):
        with open('Dos-Attack4.csv', 'a', newline='') as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerow(features)

    def get_features(self, packet):
        if packet.haslayer(sc.IP):
            # Update the flow data with the current packet
            self.update_flow(packet)

            ip_layer = packet[sc.IP]
            src = ip_layer.src
            dst = ip_layer.dst
            flow_id = (src, dst)
            subflow_id = None
            

            if packet.haslayer(sc.TCP):
                subflow_id = packet[sc.TCP].dport
            elif packet.haslayer(sc.UDP):
                subflow_id = packet[sc.UDP].dport

            if subflow_id is None:
                return

            # Calculate features
            average_packet_size = self.average_packet_size_function(flow_id)
            packet_length_mean = average_packet_size 
            packet_length_std = self.packet_length_std_function(flow_id)
            packet_length_variance = self.packet_length_variance_function(flow_id)
            #total_bwd_packet_length = self.total_bwd_packet_length_function(flow_id)
            #subflow_bwd_bytes = self.subflow_bwd_bytes_function(flow_id, subflow_id)
            #avg_bwd_segment_size = self.avg_bwd_segment_size_function(flow_id)
            #bwd_packet_length_mean = self.bwd_packet_length_mean_function(flow_id)
            total_fwd_packet_length = self.total_fwd_packet_length_function(flow_id)
            subflow_fwd_bytes = self.subflow_fwd_bytes_function(flow_id, subflow_id)
            #bwd_packet_length_max = self.bwd_packet_length_max_function(flow_id)
            max_packet_length = self.max_packet_length_function(flow_id)
            init_win_bytes_fwd = self.init_win_bytes_fwd_function(flow_id)
            fwd_packet_length_max = self.fwd_packet_length_max_function(flow_id)
            flow_iat_max = self.flow_iat_max_function(flow_id)
            #dst_port = self.destination_port_function(flow_id) 
            flow_duration = self.flow_duration_function(flow_id) 
            flow_bytes_per_sec = self.flow_bytes_per_second_function(flow_id)
            fwd_iat_max = self.fwd_iat_max_function(flow_id)
            fwd_packet_length_mean = self.fwd_packet_length_mean_function(flow_id) 
            fwd_header_length = self.fwd_header_length_function(flow_id)
            fwd_segment_size = self.flows[flow_id]['fwd_segment_size']
            fwd_iat_total = self.fwd_iat_total_function(flow_id) 
            fwd_iat_mean = self.fwd_iat_mean_function(flow_id)
            fwd_packets_per_second = self.fwd_packets_per_second_function(flow_id) 
            avg_bwd_segment_size = self.avg_bwd_segment_size_function(flow_id) 

            packet_features = [
                average_packet_size, 
                packet_length_mean,
                subflow_fwd_bytes,
                total_fwd_packet_length,
                fwd_header_length,
                fwd_packet_length_max,
                packet_length_std,
                packet_length_variance,
                max_packet_length,
                init_win_bytes_fwd,
                flow_iat_max,
                fwd_iat_max,
                flow_duration,
                fwd_segment_size,
                fwd_packet_length_mean,
                flow_bytes_per_sec,
                fwd_iat_total,
                fwd_iat_mean,
                fwd_packets_per_second,
                avg_bwd_segment_size,

            ]

            
            # Print flow ID, source IP, and destination IP
            print(f"Flow ID: {flow_id}")
            print(f"Source IP: {src}")
            print(f"Destination IP: {dst}")
            print(f"Features: Avg Packet Size: {average_packet_size:.2f} bytes,\n"
                    f"Packet Length Mean: {packet_length_mean:.2f} bytes,\n"
                    f"Packet Length Std Dev: {packet_length_std:.2f} bytes\n"
                    f"Packet Length Variance: {packet_length_variance:.2f} bytes\n"
                    f"Total FWD packet Length: {total_fwd_packet_length:.2f} bytes\n"
                    f"Subflow FWD bytes: {subflow_fwd_bytes:.2f} bytes\n"
                    f"Max Packet Length: {max_packet_length}\n"
                    f"Init Win Bytes Forward: {init_win_bytes_fwd}\n"
                    f"Forward Packet Length Max: {fwd_packet_length_max}\n"
                    f"Flow IAT Max: {flow_iat_max}\n"
                    f"Flow Duration: {flow_duration}\n"
                    f"Flow bytes/s: {flow_bytes_per_sec:.2f} bytes\n"
                    f"Fwd IAT Max: {fwd_iat_max:.2f} seconds\n"
                    f"Fwd Packet Length Mean: {fwd_packet_length_mean:.2f} bytes\n"
                    f"Fwd Header Length: {fwd_header_length:.2f} bytes\n"
                    f"FWD Segment Size: {fwd_segment_size:.2f} bytes\n"
                    f"FWD IAT Total: {fwd_iat_total:.2f} seconds\n"
                    f"FWD IAT Mean: {fwd_iat_mean:.2f} seconds\n"
                    f"FWD Packets/s: {fwd_packets_per_second:.2f} packets/s\n"
                    f"Avg BWD Segment Size: {avg_bwd_segment_size:.2f} bytes\n")

            self.save_features_to_csv(packet_features)

            return packet_features
        else:
            pass

    def predict_packet_class(self, packet):
        features = self.get_features(packet)
        if features is not None:
            features = [features]  # Convert to 2D array
            scaled_features = self.scaler.transform(features)
            pca_features = self.pca.transform(scaled_features)
            prediction = self.random_forest_model.predict(pca_features)
            return prediction[0]
        return None

    def process_packet(self, packet):
        prediction = self.predict_packet_class(packet)
        if prediction is not None:
            print(f"Predicted Class: {prediction}")
        
    def start_sniffer(self):
        bpf_filter = "ip host 192.168.1.15"
        print("Starting packet capture. Press Ctrl+C to stop.")
        sc.sniff(filter=bpf_filter, prn=self.process_packet, store=False)

    def main(self):
        self.start_sniffer()

if __name__ == '__main__':
    sniffer = Sniffer()
    sniffer.start_sniffer()

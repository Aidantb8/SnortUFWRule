import os
import logging
from scapy.all import *

# Configure logging
logging.getLogger("scapy").setLevel(logging.ERROR)

def load_snort_rules(snort_rules_dir):
    try:
        rule_files = os.listdir(snort_rules_dir)
        total_rules = len(rule_files)
        rules_processed = 0
        all_rules = []

        for rule_file in rule_files:
            if not rule_file.strip() or rule_file.startswith('#'):
                continue

            try:
                with open(os.path.join(snort_rules_dir, rule_file), 'r') as file:
                    rules = file.readlines()
                    rules_with_filename = [f"{rule_file}: {rule.strip()}" for rule in rules]
                    all_rules.extend(rules_with_filename)

                rules_processed += 1

                if rules_processed % 5 == 0:
                    progress = int((rules_processed / total_rules) * 100)
                    print(f"Loading rules: {progress}%")

            except Exception as e:
                pass

        print("Rule loading complete.")
        return all_rules
    except FileNotFoundError:
        print(f"Snort rules directory not found: {snort_rules_dir}")
        return []

def suggest_snort_rules(packet_list, existing_rules):
    rule_counts = {}

    for rule_entry in existing_rules:
        try:
            # Split the rule_entry into rule_file and rule string
            rule_file, rule = rule_entry.split(': ', 1)
        except ValueError:
            continue

        try:
            rule_id = rule.split(':')[1].split(';')[0].strip()
        except (IndexError, AttributeError):
            continue

        matching_packets = [packet for packet in packet_list if rule_id in str(packet)]

        if matching_packets:
            rule_name = rule.split()[0] if len(rule.split()) > 1 else ""
            print(f"Snort Rule {rule_id} ({rule_name}) from {rule_file} matches {len(matching_packets)} packets. Take action!")
            rule_counts[(rule_file, rule_entry)] = rule_counts.get((rule_file, rule_entry), 0) + len(matching_packets)

    return rule_counts

def suggest_ufw_rules(rule_counts):
    if rule_counts:
        print("\nUFW Rule Suggestions:")
        consolidated_rules = {}

        for (rule_file, rule_entry), count in rule_counts.items():
            try:
                # Split the rule_entry into rule_id and rule_name
                rule_id = rule_entry.split(':')[1].split(';')[0].strip()
                rule_name = rule_entry.split()[0]
            except (IndexError, AttributeError):
                continue

            consolidated_rules[(rule_id, rule_name)] = consolidated_rules.get((rule_id, rule_name), 0) + count

        for (rule_id, rule_name), total_count in consolidated_rules.items():
            ufw_rule = f"ufw insert 1 allow from any to any port 80 comment 'Snort Rule {rule_id} ({rule_name}) matches {total_count} packets'"
            print(ufw_rule)
    else:
        print("No UFW Rule Suggestions")

def capture_live_traffic(duration):
    packet_list = []

    def packet_callback(packet):
        packet_list.append(packet)

    print(f"Capturing live traffic for {duration} seconds...")
    try:
        sniff(timeout=duration, prn=packet_callback)
    except PermissionError:
        print("Error: Insufficient permissions to capture live traffic. Run the script with sudo.")
        exit()

    print(f"Captured {len(packet_list)} packets.")
    return packet_list

def read_pcap_file(pcap_path):
    try:
        packets = rdpcap(pcap_path)
        return packets
    except Exception as e:
        print(f"Error reading pcap file: {e}")
        return []

def capture_and_analyze_traffic(duration, snort_rules_dir):
    packet_list = []

    live_capture = input("Do you want to capture live traffic? (y/n): ").lower() == 'y'

    if live_capture:
        if os.geteuid() != 0:
            print("Error: Insufficient permissions to capture live traffic. Run the script with sudo.")
            exit()
        packet_list = capture_live_traffic(duration)
    else:
        pcap_path = input("Enter the path to the pcap file: ")
        packet_list = read_pcap_file(pcap_path)

    existing_snort_rules = load_snort_rules(snort_rules_dir)
    rule_counts = suggest_snort_rules(packet_list, existing_snort_rules)

    if rule_counts:
        print("\nRule Summary:")
        for (rule_file, rule_entry), count in rule_counts.items():
            try:
                rule_id = rule_entry.split(':')[1].split(';')[0].strip()
                rule_name = rule_entry.split()[0]
                print(f"Snort Rule {rule_id} ({rule_name}) matches {count} packets.")
            except (IndexError, AttributeError):
                continue
        suggest_ufw_rules(rule_counts)
    else:
        print("No Action needed")

    print("Don't use this, just use Snort")

if __name__ == "__main__":
    capture_duration = 60
    snort_rules_dir = '/etc/snort/rules'  # Update with the correct path
    capture_and_analyze_traffic(capture_duration, snort_rules_dir)
import re
import os
import pandas as pd
import yaml
from typing import Dict, Any, List, Callable
from ipaddress import IPv4Network, IPv4Address, ip_network
from collections import defaultdict
import fnmatch
import numpy as np
import csv

def netmask_to_cidr(netmask: str) -> int:
    try:
        # Handle CIDR notation
        if isinstance(netmask, str) and '/' in netmask:
            return int(netmask.strip('/'))
        # Handle integer input
        elif isinstance(netmask, int):
            return netmask
        # Handle float input (like 24.0)
        elif isinstance(netmask, float):
            return int(netmask)
        # Handle netmask format (like 255.255.248.0)
        elif isinstance(netmask, str) and '.' in netmask:
            return IPv4Network(f"0.0.0.0/{netmask}").prefixlen
        # If it's not any of the above, try to interpret as CIDR
        else:
            return int(float(str(netmask).strip()))
    except ValueError:
        print(f"Warning: Invalid netmask or CIDR: {netmask}")
        return -1  # or any other value to indicate an error

class InputTemplate:
    def __init__(self, name: str, column_mappings: Dict[str, Any], ip_format: str, 
                 mask_format: str, custom_parsers: Dict[str, Callable] = None,
                 rules: List[Dict[str, Any]] = None, file_pattern: str = None):
        self.name = name
        self.column_mappings = column_mappings
        self.ip_format = ip_format
        self.mask_format = mask_format
        self.custom_parsers = custom_parsers or {}
        self.rules = rules or []
        self.file_pattern = file_pattern

class OutputFormat:
    def __init__(self, datacenter_prefix: str):
        self.datacenter_prefix = datacenter_prefix

    def format_row(self, data: Dict[str, Any]) -> Dict[str, str]:
        network = data.get('network')
        if not network:
            raise ValueError("Network information is missing")

        return {
            "Discovery Range": f"{self.datacenter_prefix}_{network.network_address}",
            "Network IP": str(network.network_address),
            "Network mask (or bits)": f"/{network.prefixlen}",
            "Location": data.get('Location', '')
        }

def extract_datacenter_prefix(filename: str) -> str:
    match = re.match(r'([^-]+)', os.path.basename(filename))
    if match:
        return match.group(1)
    raise ValueError(f"Unable to extract datacenter prefix from filename: {filename}")

def load_templates(config_file: str) -> tuple[Dict[str, InputTemplate], Dict[str, Any]]:
    with open(config_file, 'r') as file:
        config = yaml.safe_load(file)

    templates = {}
    for template_name, template_config in config['templates'].items():
        print(f"Loading template: {template_name}")
        column_mappings = template_config['mappings']
        custom_parsers = {'to_cidr': netmask_to_cidr}
        print(f"Custom parsers for {template_name}: {custom_parsers}")
        rules = template_config.get('rules', [])

        # Convert file globbing pattern to regex pattern
        file_pattern = fnmatch.translate(template_config['file_pattern'])

        templates[template_name] = InputTemplate(
            name=template_config['name'],
            column_mappings=column_mappings,
            ip_format='cidr',  # Assume CIDR format by default
            mask_format='cidr',
            custom_parsers=custom_parsers,
            rules=rules,
            file_pattern=file_pattern
        )

    return templates, config

def is_rfc1918(ip: str) -> bool:
    try:
        ip_obj = ip_network(ip, strict=False)
        rfc1918_ranges = [
            ip_network('10.0.0.0/8'),
            ip_network('172.16.0.0/12'),
            ip_network('192.168.0.0/16')
        ]
        return any(ip_obj.overlaps(rfc1918_range) for rfc1918_range in rfc1918_ranges)
    except ValueError:
        return False

def process_file(template: InputTemplate, filename: str, config: Dict[str, Any]) -> List[Dict[str, str]]:
    datacenter_prefix = extract_datacenter_prefix(filename)
    output_format = OutputFormat(datacenter_prefix)
    processed_rows = []

    # Read the file using pandas
    if filename.endswith('.csv'):
        df = pd.read_csv(filename)
    elif filename.endswith(('.xls', '.xlsx')):
        df = pd.read_excel(filename)
    else:
        raise ValueError(f"Unsupported file format: {filename}")

    # Apply global rules
    if 'global_rules' in config:
        if config['global_rules'].get('process_only_rfc1918', False):
            ip_column = template.column_mappings['Network IP']
            if isinstance(ip_column, list):
                ip_column = ip_column[0]['column']
            df = df[df[ip_column].apply(is_rfc1918)]

        if 'ignore_cidr_less_than' in config['global_rules']:
            min_cidr = config['global_rules']['ignore_cidr_less_than']
            mask_column = template.column_mappings['Network mask (or bits)']
            if isinstance(mask_column, list):
                mask_column = mask_column[0]['column']
            df = df[df[mask_column].apply(lambda x: netmask_to_cidr(x) if pd.notnull(x) else 0) >= min_cidr]

    # Apply template-specific rules
    for rule in template.rules:
        if 'follow_column' in rule:
            follow_column = rule['follow_column']
            for_field = rule['for_field']
            df[for_field] = df[follow_column].ffill()
        elif 'ingest_only_where' in rule:
            for column, value in rule['ingest_only_where'].items():
                df = df[df[column] == value]
        elif 'ignore_row_where' in rule:
            for column, values in rule['ignore_row_where'].items():
                df = df[~df[column].isin(values)]
        elif 'strip_decimal' in rule:
            field = rule['strip_decimal']
            print(f"Applying strip_decimal to field: {field}")
            
            # First, apply strip_decimal
            df[field] = df[field].apply(strip_decimal)
            
            # Then, fill NaN values with a placeholder (e.g., -1) and convert to int
            df[field] = df[field].fillna(-1).astype('int64')
            
            print(f"Sample values after strip_decimal: {df[field].head()}")
            print(f"Data type after strip_decimal: {df[field].dtype}")

    # Process each row
    for _, row in df.iterrows():
        processed_row = {}
        for output_field, input_mapping in template.column_mappings.items():
            if isinstance(input_mapping, list):
                # Handle complex mappings
                values = []
                prefix = None
                for item in input_mapping:
                    if 'prefix' in item:
                        prefix = item['prefix']
                    elif 'column' in item:
                        value = row[item['column']]
                        if 'function' in item:
                            func_name = item['function']
                            if func_name in template.custom_parsers:
                                func = template.custom_parsers[func_name]
                                value = func(value)
                                # print(f"Applied {func_name} to {item['column']}, result: {value}")
                            else:
                                print(f"Warning: Custom parser '{func_name}' not found")
                        values.append(str(value))
                
                if prefix:
                    processed_row[output_field] = f"{prefix}{''.join(values)}"
                else:
                    processed_row[output_field] = ' '.join(values)
            else:
                processed_row[output_field] = row[input_mapping]

        # print(f"Processed row: {processed_row}")

        # Create IPv4Network object
        try:
            ip = processed_row['Network IP']
            mask = processed_row['Network mask (or bits)']
            if isinstance(mask, str) and mask.startswith('/'):
                mask = mask[1:]  # Remove leading '/' if present
            mask = int(mask)  # Ensure it's an integer
            if mask < 0 or mask > 32:
                print(f"Warning: Invalid CIDR value: {mask}")
                continue  # Skip this row
            network = IPv4Network(f"{ip}/{mask}", strict=False)
            processed_row['network'] = network
        except ValueError as e:
            print(f"Skipping invalid network: {ip}/{mask}. Error: {e}")
            continue

        formatted_row = output_format.format_row(processed_row)
        processed_rows.append(formatted_row)

    return processed_rows

def consolidate_networks(networks: List[Dict[str, str]], datacenter_prefix: str) -> List[Dict[str, str]]:
    # First, deduplicate networks based on 'Network IP' within the datacenter
    unique_networks = {}
    for network in networks:
        ip = network['Network IP']
        mask = int(network['Network mask (or bits)'].strip('/'))
        location = network['Location']
        
        if ip not in unique_networks or mask < int(unique_networks[ip]['Network mask (or bits)'].strip('/')):
            unique_networks[ip] = network

    consolidated = {}
    for network in unique_networks.values():
        ip = IPv4Address(network['Network IP'])
        mask = int(network['Network mask (or bits)'].strip('/'))
        location = network['Location']
        
        # Find the containing /16 network
        containing_16 = IPv4Network(f"{ip}/{16}", strict=False)
        key = (containing_16.network_address, location)
        
        if key not in consolidated or mask < int(consolidated[key]['Network mask (or bits)'].strip('/')):
            consolidated[key] = {
                'Discovery Range': f"{datacenter_prefix}_{containing_16.network_address}",
                'Network IP': str(containing_16.network_address),
                'Network mask (or bits)': '/16',
                'Location': location
            }
    
    return list(consolidated.values())

def strip_decimal(value):
    try:
        # Convert to float first to handle both string and float inputs
        float_value = float(value)
        # Use int() to truncate the decimal part
        return int(float_value)
    except (ValueError, TypeError):
        # If conversion fails, return NaN
        return np.nan

def main():
    print("Starting main function")
    config_file = 'template_config.yaml'
    print(f"Loading templates from {config_file}")
    templates, config = load_templates(config_file)
    print(f"Loaded {len(templates)} templates")
    
    # Add the RFC 1918 rule to global rules
    if 'global_rules' not in config:
        config['global_rules'] = {}
    config['global_rules']['process_only_rfc1918'] = True

    for template_name, template in templates.items():
        print(f"Template: {template_name}, File pattern: {template.file_pattern}")

    input_files = [
        "dc1-dc1solwind-data.xlsx",
        "dc2-effip-data.csv",
        "dc3-dc3solwind-data.xlsx",
        "dc4-infoblox-data.csv"
    ]
    print(f"Input files: {input_files}")

    # Group files by datacenter
    datacenter_files = defaultdict(list)
    for file in input_files:
        print(f"\nProcessing file: {file}")
        for template_name, template in templates.items():
            print(f"  Checking against template: {template_name}")
            print(f"    File pattern: {template.file_pattern}")
            if re.match(template.file_pattern, file):
                datacenter = template_name
                datacenter_files[datacenter].append(file)
                print(f"    Matched!")
                break
            else:
                print(f"    Not matched")
        else:
            print(f"  Warning: No matching template found for {file}")

    print(f"Grouped files by datacenter: {dict(datacenter_files)}")

    # Process and consolidate each datacenter separately
    all_consolidated_networks = []
    for datacenter, files in datacenter_files.items():
        print(f"\nProcessing datacenter: {datacenter}")
        template = templates[datacenter]
        datacenter_data = []
        datacenter_prefix = None
        for file in files:
            print(f"  Processing file: {file}")
            processed_data = process_file(template, file, config)
            print(f"    Processed {len(processed_data)} rows")
            datacenter_data.extend(processed_data)
            if datacenter_prefix is None:
                datacenter_prefix = extract_datacenter_prefix(file)
        print(f"  Total processed rows for {datacenter}: {len(datacenter_data)}")
        consolidated = consolidate_networks(datacenter_data, datacenter_prefix)
        print(f"  Consolidated networks for {datacenter}: {len(consolidated)}")
        all_consolidated_networks.extend(consolidated)

    print(f"\nTotal consolidated networks across all datacenters: {len(all_consolidated_networks)}")

    # Deduplicate based on 'Discovery Range'
    deduplicated_networks = {}
    for network in all_consolidated_networks:
        discovery_range = network['Discovery Range']
        if discovery_range not in deduplicated_networks:
            deduplicated_networks[discovery_range] = network

    final_networks = list(deduplicated_networks.values())
    print(f"Total unique networks after deduplication: {len(final_networks)}")

    # Sort the final networks based on 'Discovery Range'
    final_networks.sort(key=lambda x: x['Discovery Range'])
    
    # Write deduplicated and sorted networks to a CSV file
    output_file = 'consolidated_networks.csv'
    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = ['Discovery Range', 'Network IP', 'Network mask (or bits)', 'Location']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for network in final_networks:
            writer.writerow(network)
    
    print(f"\nDeduplicated and sorted networks have been written to {output_file}")

if __name__ == "__main__":
    main()
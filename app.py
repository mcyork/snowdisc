import re
import os
import pandas as pd
import yaml
from typing import Dict, Any, List, Callable
from ipaddress import IPv4Network, IPv4Address
from collections import defaultdict

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

def netmask_to_cidr(netmask: str) -> int:
    return IPv4Network(f"0.0.0.0/{netmask}").prefixlen

def load_templates(config_file: str) -> tuple[Dict[str, InputTemplate], Dict[str, Any]]:
    with open(config_file, 'r') as file:
        config = yaml.safe_load(file)

    templates = {}
    for template_name, template_config in config['templates'].items():
        column_mappings = template_config['mappings']
        custom_parsers = {}
        rules = []

        if 'rules' in template_config:
            for rule in template_config['rules']:
                if 'convert_netmask_to_cidr' in rule:
                    custom_parsers['to_cidr'] = netmask_to_cidr
                rules.append(rule)

        templates[template_name] = InputTemplate(
            name=template_config['name'],
            column_mappings=column_mappings,
            ip_format='cidr',  # Assume CIDR format by default
            mask_format='cidr',
            custom_parsers=custom_parsers,
            rules=rules,
            file_pattern=template_config['file_pattern']
        )

    return templates, config

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
    if 'global_rules' in config and 'ignore_cidr_less_than' in config['global_rules']:
        min_cidr = config['global_rules']['ignore_cidr_less_than']
        mask_column = template.column_mappings['Network mask (or bits)']
        if isinstance(mask_column, list):
            mask_column = mask_column[0]['column']
        df = df[df[mask_column].apply(lambda x: int(str(x).strip('/')) if pd.notnull(x) else 0) >= min_cidr]

    # Apply template-specific rules
    for rule in template.rules:
        if 'follow_column' in rule:
            follow_column = rule['follow_column']
            for_field = rule['for_field']
            df[for_field] = df[follow_column].fillna(method='ffill')
        elif 'ingest_only_where' in rule:
            for column, value in rule['ingest_only_where'].items():
                df = df[df[column] == value]
        elif 'ignore_row_where' in rule:
            for column, values in rule['ignore_row_where'].items():
                df = df[~df[column].isin(values)]

    # Process each row
    for _, row in df.iterrows():
        processed_row = {}
        for output_field, input_mapping in template.column_mappings.items():
            if isinstance(input_mapping, list):
                # Handle complex mappings
                values = []
                for item in input_mapping:
                    if 'column' in item:
                        values.append(str(row[item['column']]))
                    elif 'function' in item:
                        func = template.custom_parsers[item['function']]
                        values.append(str(func(row[item['column']])))
                processed_row[output_field] = item.get('join', '').join(values)
            else:
                processed_row[output_field] = row[input_mapping]

        # Apply any custom parsing
        for field, parser in template.custom_parsers.items():
            if field in processed_row:
                processed_row[field] = parser(processed_row[field])

        # Create IPv4Network object
        try:
            ip = processed_row['Network IP']
            mask = processed_row['Network mask (or bits)']
            network = IPv4Network(f"{ip}/{mask}", strict=False)
            processed_row['network'] = network
        except ValueError as e:
            print(f"Skipping invalid network: {ip}/{mask}. Error: {e}")
            continue

        formatted_row = output_format.format_row(processed_row)
        processed_rows.append(formatted_row)

    return processed_rows

def consolidate_networks(networks: List[Dict[str, str]]) -> List[Dict[str, str]]:
    consolidated = {}
    for network in networks:
        ip = IPv4Address(network['Network IP'])
        mask = int(network['Network mask (or bits)'].strip('/'))
        location = network['Location']
        
        # Find the containing /16 network
        containing_16 = IPv4Network(f"{ip}/{16}", strict=False)
        key = (containing_16.network_address, location)
        
        if key not in consolidated or mask < int(consolidated[key]['Network mask (or bits)'].strip('/')):
            consolidated[key] = {
                'Discovery Range': network['Discovery Range'].split('_')[0] + f"_{containing_16.network_address}",
                'Network IP': str(containing_16.network_address),
                'Network mask (or bits)': '/16',
                'Location': location
            }
    
    return list(consolidated.values())

def main():
    config_file = 'template_config.yaml'  # Path to your YAML config file
    templates, config = load_templates(config_file)

    # Use the loaded templates instead of hardcoding them
    input_files = [
        "dc1-dc1solwind-data.xlsx",
        "dc2-effip-data.csv",
        "dc3-dc3solwind-data.xlsx",
        "dc4-infoblox-data.csv"
    ]

    # Group files by datacenter
    datacenter_files = defaultdict(list)
    for file in input_files:
        for template_name, template in templates.items():
            if re.match(template.file_pattern, file):
                datacenter = template_name
                datacenter_files[datacenter].append(file)
                break

    # Process and consolidate each datacenter separately
    all_consolidated_networks = []
    for datacenter, files in datacenter_files.items():
        template = templates[datacenter]
        datacenter_data = []
        for file in files:
            datacenter_data.extend(process_file(template, file, config))
        consolidated = consolidate_networks(datacenter_data)
        all_consolidated_networks.extend(consolidated)

    # Print results (in a real scenario, you'd write this to an output file)
    print("\nConsolidated networks across all datacenters:")
    for network in all_consolidated_networks:
        print(network)

if __name__ == "__main__":
    main()
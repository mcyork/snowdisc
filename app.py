import re
import os
from typing import Dict, Any, List, Callable
from ipaddress import IPv4Network, IPv4Address
from collections import defaultdict

class InputTemplate:
    def __init__(self, name: str, column_mappings: Dict[str, str], ip_format: str, 
                 mask_format: str, location_column: str = None,
                 custom_parsers: Dict[str, Callable] = None):
        self.name = name
        self.column_mappings = column_mappings
        self.ip_format = ip_format
        self.mask_format = mask_format
        self.location_column = location_column
        self.custom_parsers = custom_parsers or {}

    def parse_row(self, row: Dict[str, Any]) -> Dict[str, Any]:
        parsed_row = {}
        for output_field, input_field in self.column_mappings.items():
            value = row.get(input_field)
            if value and output_field in self.custom_parsers:
                value = self.custom_parsers[output_field](value)
            parsed_row[output_field] = value

        # Parse IP and mask
        ip = parsed_row.get('ip')
        mask = parsed_row.get('mask')
        if ip and mask:
            parsed_row['network'] = self.parse_network(ip, mask)

        # Add location if available
        if self.location_column and self.location_column in row:
            parsed_row['location'] = row[self.location_column]

        return parsed_row

    def parse_network(self, ip: str, mask: str) -> IPv4Network:
        if self.ip_format == 'cidr':
            return IPv4Network(f"{ip}/{mask}", strict=False)
        elif self.ip_format == 'dotted_decimal':
            if self.mask_format == 'cidr':
                return IPv4Network(f"{ip}/{mask}", strict=False)
            elif self.mask_format == 'dotted_decimal':
                return IPv4Network(f"{ip}/{mask}", strict=False)
        raise ValueError(f"Unsupported IP format: {self.ip_format} or mask format: {self.mask_format}")

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
            "Location": data.get('location', '')
        }

def parse_cisco_route(route: str) -> Dict[str, Any]:
    match = re.match(r'(\S+)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})', route)
    if match:
        return {
            'type': match.group(1),
            'ip': match.group(2),
            'mask': match.group(3)
        }
    return {}

cisco_template = InputTemplate(
    name="cisco_show_ip_route",
    column_mappings={
        'route': 'Route',
        'interface': 'Interface'
    },
    ip_format='cidr',
    mask_format='cidr',
    custom_parsers={
        'route': parse_cisco_route
    }
)

ipam_template = InputTemplate(
    name="ipam_export",
    column_mappings={
        'ip': 'IP Address',
        'mask': 'Subnet Mask',
    },
    ip_format='dotted_decimal',
    mask_format='dotted_decimal',
    location_column='Location'
)

def extract_datacenter_prefix(filename: str) -> str:
    match = re.match(r'([^-]+)', os.path.basename(filename))
    if match:
        return match.group(1)
    raise ValueError(f"Unable to extract datacenter prefix from filename: {filename}")

def process_file(template: InputTemplate, filename: str) -> List[Dict[str, str]]:
    datacenter_prefix = extract_datacenter_prefix(filename)
    output_format = OutputFormat(datacenter_prefix)
    processed_rows = []

    # This is a placeholder for file reading logic
    # In a real implementation, you would read the file and iterate over its rows
    with open(filename, 'r') as file:
        for row in file:  # This is simplified; you'll need to parse the file based on its format
            parsed_data = template.parse_row(row)
            processed_row = output_format.format_row(parsed_data)
            processed_rows.append(processed_row)

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

def process_and_consolidate_datacenter(files: List[str], templates: Dict[str, InputTemplate]) -> List[Dict[str, str]]:
    all_data = []
    for file in files:
        file_extension = os.path.splitext(file)[1].lower()
        if file_extension in templates:
            template = templates[file_extension]
            all_data.extend(process_file(template, file))
        else:
            print(f"Warning: No template found for file {file}. Skipping.")
    
    return consolidate_networks(all_data)

def main():
    # Define templates for different file types
    templates = {
        '.txt': cisco_template,
        '.csv': ipam_template,
        # Add more templates for other file types as needed
    }

    # Simulate a directory of input files
    input_files = [
        "datacenter1-cisco-routes.txt",
        "datacenter1-ipam-export.csv",
        "datacenter2-cisco-routes.txt",
        "datacenter2-solarwinds-export.csv",
        "datacenter3-efficientip-export.csv"
    ]

    # Group files by datacenter
    datacenter_files = defaultdict(list)
    for file in input_files:
        datacenter = extract_datacenter_prefix(file)
        datacenter_files[datacenter].append(file)

    # Process and consolidate each datacenter separately
    all_consolidated_networks = []
    for datacenter, files in datacenter_files.items():
        consolidated = process_and_consolidate_datacenter(files, templates)
        all_consolidated_networks.extend(consolidated)

    # Print results (in a real scenario, you'd write this to an output file)
    print("\nConsolidated networks across all datacenters:")
    for network in all_consolidated_networks:
        print(network)

if __name__ == "__main__":
    main()

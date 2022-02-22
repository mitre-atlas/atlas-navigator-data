from argparse import ArgumentParser
from copy import deepcopy
from datetime import datetime
import json
from pathlib import Path
import re

import yaml


"""Converts ATLAS YAML data to ATT&CK Navigator layers."""

# Captures the technique ID of a top-level technique or subtechnique ID
TECHNIQUE_ID_REGEX = re.compile(r'^(AML\.T\d{4})')

def generate_individual_case_study_layers(matrix, output_dir, layer_data, navigator_technique_objs,
    individual_case_study_layer_directory='case-study-navigator-layers'):
    """Outputs a layer JSON file highlighting techniques used in each individual case study."""
    # Iterates through each case study
    for case_study in matrix['case-studies']:
        # Title at the top of the Navigator tab
        name = case_study['name']
        case_study_id = case_study['id']
        # Appears in layer dropdown
        summary = case_study['summary']
        # Highlight color
        color = '#C8E6C9' # Light green

        techniques = []

        # Output a layer file for each case study
        for step in case_study['procedure']:
            technique_id = step['technique']
            # Subtechniques have ID format ex. AML.T0000.000
            is_subtechnique = (technique_id.count('.') == 2)

            if is_subtechnique:
                # Key into navigator technique objs is just the ID for subtechniques
                key = technique_id
                 # Access the corresponding navigator technique object
                technique_obj = deepcopy(navigator_technique_objs[key])
                # Add the highlight color
                technique_obj.update({
                    'color': color
                })
                techniques.append(technique_obj)

                # Parse out the parent ID
                parent_technique_id = TECHNIQUE_ID_REGEX.match(technique_id).group()
                # Retrieve the parent technique object, which has show subtechniques enabled
                parent_technique_key = f"{parent_technique_id}_{step['tactic']}"
                parent_technique_obj = deepcopy(navigator_technique_objs[parent_technique_key])
                # Add parent technique navigator obj to list
                techniques.append(parent_technique_obj)

            else:
                # Is top-level technique, ex. AML.T0000
                # Key is technique ID combined with tactic ID
                key = f"{technique_id}_{step['tactic']}"
                # Access the corresponding navigator technique object
                technique_obj = deepcopy(navigator_technique_objs[key])
                # Add the highlight color and disable showing subtechniques
                technique_obj.update({
                    'color': color,
                    'showSubtechniques': False
                })
                techniques.append(technique_obj)

        # Construct layer data
        individual_case_study_layer_data = {
            'name': name,
            'description': summary,
            'techniques': techniques,
            'legendItems': [
                {
                    'label': 'Used in case study',
                    'color': color
                }
            ],
            'metadata': [
                {
                    'name': 'url',
                    'value': f'https://atlas.mitre.org/studies/{case_study_id}'
                }
            ]
        }

        # Update metadata with passed-in metadata
        individual_case_study_layer_data['metadata'].extend(
            deepcopy(layer_data['metadata'])
        )

        individual_case_study_layer_data = { **layer_data, **individual_case_study_layer_data}

        # Define output filename
        dir_path = output_dir / individual_case_study_layer_directory
        filename = f'{case_study_id}.json'
        # Write JSON to file
        write_to_json_file(individual_case_study_layer_data, dir_path, filename)

    print(f"{len(matrix['case-studies'])} case study layer files outputted to {dir_path}")

def generate_case_study_frequency_layer(matrix, output_dir, layer_data, navigator_technique_objs, layer_output_directory='default-navigator-layers'):
    """Outputs a layer JSON file with a gradient showing the number of case studies in which
    each technique is used.
    """

    num_case_studies = len(matrix['case-studies'])

    # Title at the top of the Navigator tab
    name = 'ATLAS Case Study Frequency'
    # Appears in layer dropdown
    description = f'Heatmap of technique occurrences in {num_case_studies} ATLAS case studies'

    # Add initial score to Navigator technique objects
    techniques = deepcopy(navigator_technique_objs)
    for technique in techniques.values():
        technique.update({
            'score': 0
        })

    # Output a layer file for each case study
    for case_study in matrix['case-studies']:
        for step in case_study['procedure']:
            technique_id = step['technique']
            # Subtechniques have ID format ex. AML.T0000.000
            is_subtechnique = (technique_id.count('.') == 2)

            if is_subtechnique:
                # Key into navigator technique objs is just the ID for subtechniques
                key = technique_id
            else:
                # Is top-level technique, ex. AML.T0000
                # Key is technique ID combined with tactic ID
                key = f"{technique_id}_{step['tactic']}"

            # Increment the score on the corresponding technique object
            techniques[key]['score'] += 1

    # Construct layer data
    case_study_layer_data = {
        'name': name,
        'description': description,
        'techniques': list(techniques.values()), # List of techniques is inside dictionary
        'gradient': {
            'colors': [
                '#FFFFFF',
                '#F44336'
            ],
            'minValue': 0,
            'maxValue': num_case_studies # i.e. appears in every study
        },
    }
    # Combine with default layer data
    case_study_layer_data = { **layer_data, **case_study_layer_data}

    # Define output filename
    dir_path = output_dir / layer_output_directory
    case_study_frequency_filename = 'atlas_case_study_frequency.json'
    # Write JSON to file
    write_to_json_file(case_study_layer_data, dir_path, case_study_frequency_filename)

    print(f'Case study frequency layer outputted to {dir_path / case_study_frequency_filename}')

def generate_matrix_layer(output_dir, layer_data, navigator_technique_objs, matrix_layer_directory='default-navigator-layers'):
    """Outputs a layer JSON file highlighting the techniques used in ATLAS."""

    # Redefine name and description
    name = 'ATLAS Matrix'
    description = 'Adversarial Threat Landscape for Artificial-Intelligence Systems, see atlas.mitre.org'

    # Technique highlight color
    color = '#C8E6C9' # Light green

    # Add color to Navigator technique objects
    techniques = deepcopy(list(navigator_technique_objs.values()))
    for technique in techniques:
        technique.update({
            'color': color
        })

    # Construct layer data
    matrix_layer_data = {
        'name': name,
        'description': description,
        'techniques': techniques,
        'legendItems': [
            {
                'label': 'ATLAS technique',
                'color': color
            }
        ]
    }
    # Combine with default layer data
    matrix_layer_data = { **layer_data, **matrix_layer_data }

    # Define output filename
    dir_path = output_dir / matrix_layer_directory
    matrix_filename = 'atlas_layer_matrix.json'
    # Write JSON to file
    write_to_json_file(matrix_layer_data, dir_path, matrix_filename)

    print(f'Matrix layer outputted to {dir_path / matrix_filename}')

def build_navigator_technique_objs(matrix):
    """Returns a dictionary of Navigator layer technique objects from the provided ATLAS data.

    https://github.com/mitre-attack/attack-navigator/blob/master/layers/LAYERFORMATv4.md
    """
    # Build mapping of tactic ID to Navigator tactic name
    navigator_tactic_names = {}
    for tactic in matrix['tactics']:
        # Navigator tactic names are lowercase with hyphens in place of spaces
        navigator_tactic_names[tactic['id']] = tactic['name'].replace(' ','-').lower()

    # Track Navigator technique objects
    # Keyed by unique key `techniqueID_tacticID` or `subtechniqueID`
    objs = {}

    for technique in matrix['techniques']:
        technique_id = technique['id']

        if 'tactics' in technique:
            # This is a top-level technique
            for tactic_id in technique['tactics']:
                obj = {
                    'techniqueID': technique_id,
                    'showSubtechniques': True,
                    'tactic': navigator_tactic_names[tactic_id]
                }
                objs[f'{technique_id}_{tactic_id}'] = obj

        else:
            # Otherwise, is a subtechnique
            obj = {
                'techniqueID': technique_id
            }
            objs[f'{technique_id}'] = obj

    return objs

def write_to_json_file(obj, output_dir, filename):
    """Outputs the specified object to JSON file,
    Creates the output directory if not exists.
    """
    # Assumes a Path directory param - if passed a string, convert to a Path
    if not isinstance(output_dir, Path) and isinstance(output_dir, str):
        output_dir = Path(output_dir)

    # Create the output directory if needed, included nested directories
    output_dir.mkdir(parents=True, exist_ok=True)

    # Construct output filepath
    output_filepath = output_dir / filename

    # Write JSON to file
    with open(output_filepath, 'w') as f:
        json.dump(obj, f, indent=4)

if __name__ == '__main__':
    """Main entry point to ATLAS Navigator layer JSON file generation."""
    parser = ArgumentParser(
        description = 'Creates a Navigator JSON Layer files showing tactics and techniques used by ATLAS.'
    )

    # Input file
    parser.add_argument('-f',
        type=str,
        dest='atlas_data_filepath',
        default='atlas-data/dist/ATLAS.yaml',
        help='Path to ATLAS.yaml file'
    )
    # Output directory
    parser.add_argument('-o',
        type=str,
        dest='output_dir',
        default='dist',
        help='Output directory for generated files'
    )
    # Matrix layer gets updated when tactics and techniques change
    # Case study frequency layer and individual layers get updated whenever case studies change
    parser.add_argument('-l', '--layer',
        choices = ['matrix', 'case_study'],
        dest = 'layer',
        help = 'Output specific layers, otherwise outputs all'
    )

    args = parser.parse_args()

    # Create output directories as needed
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Load ATLAS data
    with open(args.atlas_data_filepath) as f:
        data = yaml.safe_load(f)

    # Define common Navigator layer info
    # nav-app/src/assets/config.json's version name before the 'vX' - domain name
    domain = 'atlas-atlas'

    # Base for all layers
    layer_data = {
        'versions': {
            'layer': '4.3',
            'navigator': '4.5.5'
        },
        'domain': domain,
        'metadata': [
            {
                'name': 'atlas_data_version',
                'value': str(data['version'])
            },
            {
                'name': 'generated_on',
                'value': datetime.now().strftime('%Y-%m-%d')
            }
        ]
    }

    navigator_technique_objs = build_navigator_technique_objs(data)

    if args.layer is None or args.layer == 'matrix':
        # Generate highlight layer that for ATLAS techniques
        generate_matrix_layer(output_dir, layer_data, navigator_technique_objs)

    if args.layer is None or args.layer == 'case_study':
        # Generate heatmap layer for techniques in case studies
        generate_case_study_frequency_layer(data, output_dir, layer_data, navigator_technique_objs)
        # Generate highlight layers for techniques used in each case study
        generate_individual_case_study_layers(data, output_dir, layer_data, navigator_technique_objs)

    print('Done!')
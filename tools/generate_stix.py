from argparse import ArgumentParser
import datetime
import json
from pathlib import Path
import uuid

import requests
from stix2 import MemoryStore, properties
from stix2.v21 import AttackPattern, Bundle, CourseOfAction, CustomObject, ExternalReference, Identity, KillChainPhase, Relationship
import yaml

"""
Custom MITRE ATT&CK STIX object to be able to use the Navigator.
        https://github.com/mitre/cti/blob/master/USAGE.md#the-attck-data-model
        https://stix2.readthedocs.io/en/latest/guide/custom.html?highlight=custom#Custom-STIX-Object-Types
"""
@CustomObject('x-mitre-tactic', [
    ('name', properties.StringProperty()),
    ('description', properties.StringProperty()),
    # https://github.com/oasis-open/cti-python-stix2/blob/master/stix2/properties.py#L197
    ('external_references', properties.ListProperty(ExternalReference)),
    ('x_mitre_shortname', properties.StringProperty()),
])
class AttackTactic():
    """Custom MITRE ATT&CK tactic STIX object."""
    def __init__(self, **kwargs):
        pass

@CustomObject('x-mitre-matrix', [
    ('name', properties.StringProperty()),
    ('description', properties.StringProperty()),
    # https://github.com/oasis-open/cti-python-stix2/blob/master/stix2/properties.py#L197
    ('external_references', properties.ListProperty(ExternalReference)),
    ('tactic_refs', properties.ListProperty(properties.ReferenceProperty(valid_types='x-mitre-tactic')))
])
class AttackMatrix():
    """Custom MITRE ATT&CK matrix STIX object."""
    def __init__(self, **kwargs):
        pass

# Collection object modeled as ATT&CK collection
# https://github.com/center-for-threat-informed-defense/attack-workbench-frontend/blob/master/docs/collections.md#object-version-reference-properties
@CustomObject('x-mitre-collection', [
    ('type', properties.StringProperty()),
    ('id', properties.IDProperty(type='x-mitre-collection')),
    ('name', properties.StringProperty()),
    ('description', properties.StringProperty()),
    ('created', properties.TimestampProperty()),
    ('modified', properties.TimestampProperty()),
    ('x_mitre_version', properties.StringProperty()),
    ('spec_version', properties.StringProperty()),
    ('x_mitre_attack_spec_version', properties.StringProperty()),
    ('created_by_ref', properties.ReferenceProperty(valid_types='identity')),
    ('object_marking_refs', properties.ListProperty(properties.IDProperty(type='x-mitre-collection'))),
    ('x_mitre_contents', properties.ListProperty(properties.DictionaryProperty())),
])
class AttackCollection():
    """Custom MITRE ATT&CK collection STIX object."""
    def __init__(self, **kwargs):
        pass

class ATLAS:
    """Converts from ATLAS YAML data to STIX."""

    def __init__(self, atlas_data, source_name, existing_stix_json=None):
        """Initialize an ATLAS object.  Defaults provided via arguments in main.

        Args:
            atlas_data (str): Dictionary of ATLAS.yaml data
        """
        self.uuid_domain = uuid.UUID("atlas.mitre.org.".encode("utf-8").hex())
        self.source_name = source_name
        self.parse_data_files(atlas_data)
        # Track ATLAS tactics by short ID for matrix ordering lookup
        self.tactic_mapping = {}
        # Existing STIX JSON, i.e. for ATT&CK Enterprise data
        self.existing_stix_json = existing_stix_json

    def parse_data_files(self, atlas_data):
        """Sets attributes from the ATLAS data."""
        # Top-level metadata
        self.data_id = atlas_data['id']
        self.data_name = atlas_data['name']
        self.data_version = atlas_data['version']

        # Collect data objects across all matrices
        self.matrices = atlas_data['matrices']
        self.tactics = [obj for matrix in self.matrices if 'tactics' in matrix for obj in matrix['tactics']]
        self.techniques = [obj for matrix in self.matrices if 'techniques' in matrix for obj in matrix['techniques']]
        self.mitigations = [obj for matrix in self.matrices if 'mitigations' in matrix for obj in matrix['mitigations']]
        self.attack_derived_techniques = [obj for obj in self.techniques if 'ATT&CK-reference' in obj]

    def find_stix_technique_by_external_ref_id(self, stix_objects, external_ref_id):
        """Returns the corresponding STIX technique object for an ATLAS ID, or None if none are found."""
        # Look for an ATT&CK technique that has the corresponding ID
        return next((obj for obj in stix_objects if obj['type'] == 'attack-pattern' and obj['external_references'][0]['external_id'] == external_ref_id), None)

    def to_stix_json(self, stix_output_filepath, atlas_url, identity_name):
        """Saves a STIX JSON file of the ATLAS tactics and techniques info.

        STIX Bundle specs
        https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_nuwp4rox8c7r
        """

        # Convert ATLAS techniques first to populate the referenced ATT&CK tactics
        # Only for parent techniques, as subtechniques do not have tactics references
        stix_techniques = []
        relationships = []
        parent_technique = None
        for t in self.techniques:
            # Indicate ATT&CK-adapted techniques where applicable
            if self.existing_stix_json and t in self.attack_derived_techniques:
                # Look for an ATT&CK technique that has the corresponding ID
                attack_obj = self.find_stix_technique_by_external_ref_id(self.existing_stix_json['objects'], t['ATT&CK-reference']['id'])
                if attack_obj:
                    # Rename both techniques to distinguish
                    t['name'] = f"{t['name']} (ATLAS)"

            if 'subtechnique-of' in t:
                # Create subtechnique and relationship
                subtechnique, relationship = self.subtechnique_to_attack_pattern(t, parent_technique, atlas_url)
                # Add to trackers
                stix_techniques.append(subtechnique)
                relationships.append(relationship)
            else:
                # Create and add this technique
                technique = self.technique_to_attack_pattern(t, atlas_url)
                stix_techniques.append(technique)
                # Save off reference to this technique for use by its subtechniques, should there be any following
                parent_technique = technique

        print(f'Converted {len(stix_techniques)} techniques ({len(stix_techniques) - len(relationships)} top-level, {len(relationships)} subtechniques) to STIX objects.')
        print(f'Created {len(relationships)} subtechnique relationships.')

        # Convert ATLAS tactics to x-mitre-tactics
        stix_tactics = [self.tactic_to_mitre_attack_tactic(t, atlas_url) for t in self.tactics]
        print(f'Converted {len(stix_tactics)} tactics to STIX objects.')

        # Convert ATLAS mitigations to course-of-action and "mitigates" relationships
        # List of [(mitigation, relationship[])] to [(mitigations,), (relationships,)]
        stix_mitigations = []
        stix_mitigation_relationships = []
        for m in self.mitigations:
            stix_mitigation, mitigation_relationships = self.mitigation_to_course_of_action(m, stix_techniques, atlas_url)
            stix_mitigations.append(stix_mitigation)
            stix_mitigation_relationships.extend(mitigation_relationships)

        print(f'Converted {len(stix_mitigations)} mitigations to STIX objects.')
        print(f'Created {len(stix_mitigation_relationships)} mitigation-technique relationships.')

        # Add mitigation relationships to broader list of all relationships
        relationships.extend(stix_mitigation_relationships)


        # Build x-mitre-matrix

        # Controls location of "View tactic/technique" on Navigator item right-click
        external_references = [
            ExternalReference(
                source_name = self.source_name,
                url=atlas_url,
                external_id = self.source_name # https://github.com/mitre-attack/attack-navigator/issues/362
            )
        ]

        # Construct a x-mitre-matrix for each matrix defined in the data
        stix_matrices = []

        for matrix in self.matrices:
            # Build ordered list of tactics
            tactic_refs = []

            # Order of tactics in matrix, by STIX ID reference
            tactic_refs = [self.tactic_mapping[tactic['id']]['id'] for tactic in matrix['tactics']]

            print(f'\tGenerated {len(tactic_refs)} tactic references for matrix with ID {matrix["id"]}')

            matrix_uuid = uuid.uuid5(self.uuid_domain, "ATLAS-matrix")
            stix_matrix_obj = AttackMatrix(
                id=f"x-mitre-matrix--{matrix_uuid}",
                name=f'{matrix["name"]}',
                description=f'{self.data_id} matrix for {matrix["name"]}',
                external_references=external_references,
                tactic_refs=tactic_refs,
                allow_custom=True
            )

            stix_matrices.append(stix_matrix_obj)

        print(f'Created {len(stix_matrices)} STIX matrix objects.')

        # Combine all STIX data objects into a single list for bundling
        stix_data_objects = stix_tactics + stix_techniques + stix_mitigations + relationships + stix_matrices

        # Create new properties for collection use
        # Store current datetime
        curr_datetime = datetime.datetime.utcnow()
        # Identity for this script's user and URL
        identity_uuid = uuid.uuid5(self.uuid_domain, "ATLAS-identity")
        identity = Identity(id=f"identity--{identity_uuid}", name=identity_name, description=atlas_url)


        # Fill collection's default fields
        # https://github.com/center-for-threat-informed-defense/attack-workbench-frontend/blob/master/docs/collections.md#object-version-reference-properties
        collection_uuid = uuid.uuid5(self.uuid_domain, "ATLAS-collection")
        stix_collection_obj = AttackCollection(
            id=f"x-mitre-collection--{collection_uuid}",
            type='x-mitre-collection',
            name = f'{self.data_id}',
            description = f'{self.data_name}',
            #created = curr_datetime,
            #modified = curr_datetime,
            spec_version = '2.1',
            x_mitre_version = '0.1',
            x_mitre_attack_spec_version = '2.1.0',
            created_by_ref = identity.id,
            object_marking_refs = [],
            # Loop through data objects to store their references in this collection
            x_mitre_contents = [{ 'object_ref': obj.id, 'object_modified': obj.modified } for obj in stix_data_objects]
        )
        print(f'Created STIX collection object.')

        # JSON
        print('Bundling and serializing ATLAS data to JSON file...')
        bundle_uuid = uuid.uuid5(self.uuid_domain, "ATLAS-bundle")
        bundle = Bundle(
            id=f"bundle--{bundle_uuid}",
            objects= stix_data_objects + [stix_collection_obj], # Collection is bundled along with data
            allow_custom=True # Needed as ATT&CK data has custom objects
        )

        # Convert to JSON
        stix_json = json.loads(bundle.serialize())

        if self.existing_stix_json:
            # Delete the existing ATT&CK Enterprise x-mitre-matrix object to prevent two matrices from appearing
            is_enterprise_matrix = lambda obj: 'type' in obj and obj['type'] == 'x-mitre-matrix' and 'name' in obj and obj['name'] == 'Enterprise ATT&CK'

            existing_objs = []
            for obj in self.existing_stix_json['objects']:
                # Exclude the ATT&CK Enterprise matrix object
                if not is_enterprise_matrix(obj):
                    # Add atlas-atlas domain ATT&CK Enterprise objects to ensure visibility
                    if 'x_mitre_domains' in obj and 'enterprise-attack' in obj['x_mitre_domains']:
                        obj['x_mitre_domains'].append('atlas-atlas')

                    # Collect objects
                    existing_objs.append(obj)

            print('Adding custom STIX objects to the existing STIX JSON objects...')
            # Add custom STIX objects to the existing STIX's objects
            existing_objs.extend(stix_json['objects'])
            self.existing_stix_json['objects'] = existing_objs

            # Save to file
            with open(stix_output_filepath, 'w') as f:
                json.dump(self.existing_stix_json, f)

        else:
            # Save to file
            with open(stix_output_filepath, 'w') as f:
                json.dump(stix_json, f)

        print(f'Done! See {stix_output_filepath}\n')

    def referenced_tactics_to_kill_chain_phases(self, tactic_ids):
        """Converts a list of tactic IDs referenced by a technique
        to a list of STIX Kill Chain Phases.

        Kill Chain Phase spec:
        https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_i4tjv75ce50h
        """
        kill_chain_phases = []

        for tactic_id in tactic_ids:

            kill_chain_name = self.source_name # Using this as an identifier

            # Look up ATLAS tactic name
            tactic = next((tactic for tactic in self.tactics if tactic['id'] == tactic_id), None)
            # Ensure this is found
            if tactic is None:
                raise ValueError(f'Could not find tactic object with ID {tactic_id}')

            # Convert name to lowercase and hyphens to fit spec
            phase_name = tactic['name'].lower().replace(' ', '-')

            # Create and add
            kcp = KillChainPhase(
                kill_chain_name=kill_chain_name,
                phase_name=phase_name
            )
            kill_chain_phases.append(kcp)

        return kill_chain_phases

    def build_atlas_external_references(self, t, atlas_url, route='techniques'):
        """Returns a STIX External Reference for ATLAS data."""

        # Construct the full URL to the resource
        url = atlas_url + '/' + route + '/' + t['id']

        # External references is a list
        return [
            ExternalReference(
                source_name=self.source_name, # The only required property
                url=url,
                external_id=t['id']
            )
        ]

    def tactic_to_mitre_attack_tactic(self, t, atlas_url):
        """Returns a STIX x-mitre-tactic representing this tactic."""
        tactic_uuid = uuid.uuid5(self.uuid_domain, t['id'])
        at = AttackTactic(
            id=f"x-mitre-tactic--{tactic_uuid}",
            name=t['name'],
            description=t['description'],
            external_references=self.build_atlas_external_references(t, atlas_url, 'tactics'),
            x_mitre_shortname=t['name'].lower().replace(' ','-'),
            created=t['created_date'],
            modified=t['modified_date'],
        )

        # Track this tactic by short ID
        self.tactic_mapping[t['id']] = at

        return at

    def technique_to_attack_pattern(self, t, atlas_url):
        """Returns a STIX AttackPattern representing this technique."""
        technique_uuid = uuid.uuid5(self.uuid_domain, t['id'])
        return AttackPattern(
            id=f"attack-pattern--{technique_uuid}",
            name=t['name'],
            description=t['description'],
            kill_chain_phases=self.referenced_tactics_to_kill_chain_phases(t['tactics']),
            external_references=self.build_atlas_external_references(t, atlas_url),
            # Needed by Navigator else TypeError technique.platforms is not iterable
            allow_custom=True,
            x_mitre_platforms=['ATLAS'],
            created=t['created_date'],
            modified=t['modified_date'],
        )

    def subtechnique_to_attack_pattern(self, t, parent, atlas_url):
        """Returns a STIX AttackPattern representing this subtechnique and a STIX Relationship
        between this subtechnique and its parent.

        https://github.com/mitre/cti/blob/master/USAGE.md#sub-techniques
        """
        subtechnique_uuid = uuid.uuid5(self.uuid_domain, t['id'])
        subtechnique = AttackPattern(
            id=f"attack-pattern--{subtechnique_uuid}",
            name=t['name'],
            description=t['description'],
            kill_chain_phases=parent.kill_chain_phases,
            external_references=self.build_atlas_external_references(t, atlas_url),
            # Needed by Navigator else TypeError technique.platforms is not iterable
            allow_custom=True,
            x_mitre_platforms=['ATLAS'],
            x_mitre_is_subtechnique=True,
            created=t['created_date'],
            modified=t['modified_date'],
        )

        relationship_uuid = uuid.uuid5(self.uuid_domain, f"{t['id']}-subtechnique-of-{parent.id}")
        relationship = Relationship(
            id=f"relationship--{relationship_uuid}",
            source_ref=subtechnique.id,
            relationship_type='subtechnique-of',
            target_ref=parent.id,
            created=t['created_date'],
            modified=t['modified_date'],
        )

        return subtechnique, relationship

    def mitigation_to_course_of_action(self, m, stix_techniques, atlas_url):
        """Returns a STIX CourseOfAction representing this mitigation and STIX Relationships
        between this mitigation and any techniques addressed by it.

        https://github.com/mitre/cti/blob/master/USAGE.md#mitigations
        """
        mitigation_uuid = uuid.uuid5(self.uuid_domain, m['id'])
        mitigation = CourseOfAction(
            id=f"course-of-action--{mitigation_uuid}",
            name=m['name'],
            description=m['description'],
            external_references=self.build_atlas_external_references(m, atlas_url, route='mitigations'),
            created=m['created_date'],
            modified=m['modified_date'],
        )

        relationships = []

        # A mitigation may optionally have associated technique uses
        if 'techniques' in m:
            for technique_use in m['techniques']:
                # technique is { id: , use: }
                stix_technique = self.find_stix_technique_by_external_ref_id(stix_techniques, technique_use['id'])

                if stix_technique:
                    relationship_uuid = uuid.uuid5(self.uuid_domain, f"{m['id']}-mitigates-{technique_use['use']}")
                    relationship = Relationship(
                        id=f"relationship--{relationship_uuid}",
                        source_ref=mitigation.id,
                        relationship_type='mitigates',
                        target_ref=stix_technique.id,
                        description=technique_use['use'],
                        created=m['created_date'],
                        modified=m['modified_date'],
                    )

                    relationships.append(relationship)

        return mitigation, relationships


def get_latest_attack_stix_json(domain='enterprise-attack'):
    """Retrieves the ATT&CK STIX data from MITRE/CTI as a MemoryStore.
    Domain should be 'enterprise-attack', 'mobile-attack' or 'ics-attack'. Branch should typically be master.
    Adapted from https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md#accessing-attck-data-in-python
    """
    stix_json = requests.get(f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/{domain}/{domain}.json", verify=False).json()
    return stix_json

if __name__ == '__main__':
    """Main entry point to STIX file generation for ATLAS data."""

    parser = ArgumentParser(
        description="Creates a STIX JSON file showing tactics and techniques used by ATLAS."
    )
    parser.add_argument("-f",
        type=str,
        dest="atlas_data_filepath",
        default="atlas-data/dist/ATLAS.yaml",
        help="Path to ATLAS.yaml file"
    )
    parser.add_argument("--url",
        type=str,
        dest="atlas_url",
        default="https://atlas.mitre.org",
        help="URL to ATLAS website for Navigator item linking"
    )
    parser.add_argument("--source_name",
        type=str,
        dest="source_name",
        default="mitre-atlas",
        help="A lowercase, hyphenated identifier for this data"
    )
    parser.add_argument("--identity_name",
        type=str,
        dest="identity_name",
        default="MITRE ATLAS",
        help="Name of the creator identity"
    )
    parser.add_argument("-o",
        type=str,
        dest="output_filepath",
        default="dist/stix-atlas.json",
        help="Output filepath for STIX JSON"
    )
    parser.add_argument("--include-attack",
        dest="include_attack",
        default=False,
        action="store_true",
        help="Whether to include the latest version of ATT&CK Enterprise data"
    )

    args = parser.parse_args()

    # Create output directories as needed
    output_filepath = Path(args.output_filepath)
    output_filepath.parent.mkdir(parents=True, exist_ok=True)

    with open(args.atlas_data_filepath) as f:
        # Load in ATLAS data
        data = yaml.safe_load(f)

        attack_stix_json = None
        if args.include_attack:
            # https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md#accessing-attck-data-in-python
            attack_stix_json = get_latest_attack_stix_json()

        # Initialize ATLAS-to-STIX structures
        atlas = ATLAS(data, args.source_name, attack_stix_json)

         # Convert to and save STIX
        atlas.to_stix_json(output_filepath, args.atlas_url, args.identity_name, )

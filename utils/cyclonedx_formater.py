import datetime
import pytz
from cyclonedx.model.bom import Bom
from cyclonedx.model.tool import Tool
from cyclonedx.model.component import Component, ComponentType, PackageURL
from cyclonedx.model.dependency import Dependency
from cyclonedx.output import make_outputter
from cyclonedx.output.json import JsonV1Dot6
from cyclonedx.schema import SchemaVersion, OutputFormat
from cyclonedx.validation.json import JsonStrictValidator
from cyclonedx.exception import MissingOptionalDependencyException
from collections import OrderedDict
import sys
import json
import re

import pkg_resources

def validate_package_name(package_name):
    # Check if the package name contains only valid characters
    if re.match(r'^[a-zA-Z0-9-_]+$', package_name):
        return True
    return False

def get_package_versions(package_name, visited=None):
    transitive_dependencies = []
    if visited is None:
        visited = set()
    try:
        dist = pkg_resources.get_distribution(package_name)
    except pkg_resources.DistributionNotFound:
        print(f"{package_name} (not installed)")
        return transitive_dependencies  # Return an empty list if not installed

    if package_name in visited:
        # print(f"{package_name} (already visited)")
        return transitive_dependencies  # Return an empty list if already visited

    # Add package name and version to the visited set
    visited.add((package_name, dist.version))
    transitive_dependencies.append((package_name, dist.version))
    print(f"{dist.project_name}=={dist.version}")

    for requirement in dist.requires():
        transitive_dependencies.extend(get_package_versions(requirement.project_name, visited))

    # Print the visited packages with their versions
    print(f"Visited: {', '.join([f'{pkg}=={ver}' for pkg, ver in visited])}. Moving on to next package")
    
    return transitive_dependencies  # Return the list of dependencies

def extract_package_info(tags):
    for tag in tags:
        if 'maven_coordinates=' in tag:
            # Maven format: group:artifact:version
            coords = tag.split('=')[1].split(':')
            if len(coords) >= 3:
                group_id, artifact_id, version = coords[0], coords[1], coords[2]
                return f"{group_id}.{artifact_id}", version, "maven"
        elif 'pypi_name=' in tag:
            # PyPI format: separate name and version tags
            name = tag.split('=')[1]
            version = next((t.split('=')[1] for t in tags if 'pypi_version=' in t), "unknown")
            return name, version, "pypi"
    
    # Default case if no matching tags found
    return None, "unknown", None

def create_package_url(package_name, version, purl_type):
    """
    Create a PackageURL object based on the package type.
    
    Args:
        package_name (str): Name of the package
        version (str): Version of the package
        purl_type (str): Type of package (maven or pypi)
        
    Returns:
        PackageURL: CycloneDX PackageURL object
    """
    if purl_type == "maven":
        # Handle Maven package names which might contain dots
        group_artifact = package_name.split('.')
        if len(group_artifact) > 1:
            group_id = '.'.join(group_artifact[:-1])
            artifact_id = group_artifact[-1]
            return PackageURL(type='maven', namespace=group_id, name=artifact_id, version=version)
    
    # PyPI packages
    if purl_type == "pypi":
        return PackageURL(type='pypi', name=package_name, version=version)
    else:
        return PackageURL(type='generic', name=package_name, version=version)

def determine_component_type(bazel_deps):
    """
    Determine the main component type based on bazel_deps structure.
    
    Args:
        bazel_deps (dict): The Bazel dependencies dictionary
        
    Returns:
        str: 'maven', 'pypi', or 'generic'
    """
    # First check if it's a direct dependency structure
    if any('maven_coordinates=' in str(tags) for _, details in bazel_deps.items() for tags in details.get('tags', [])):
        return 'maven'
    if any('pypi_name=' in str(tags) for _, details in bazel_deps.items() for tags in details.get('tags', [])):
        return 'pypi'
    
    # Then check if it's a nested structure
    if isinstance(bazel_deps, dict):
        if 'maven' in bazel_deps:
            return 'maven'
        if 'pypi' in bazel_deps:
            return 'pypi'
    
    return 'generic'

def generate_cyclonedx_sbom(bazel_deps, main_component_name="project"):
    """
    Generate a CycloneDX SBOM from Bazel dependencies.

    Args:
        bazel_deps (dict): The Bazel dependencies.
        main_component_name (str): Name of the main component.

    Returns:
        dict: A CycloneDX SBOM.
    """
    # Determine component type
    component_type = determine_component_type(bazel_deps)
    
    # Create a CycloneDX BOM object
    bom = Bom()
    
    # Define the main component of the project
    main_component = Component(
        name=main_component_name,
        version="0.0.0",
        type=ComponentType.APPLICATION,
        bom_ref=f"1-{main_component_name}@0.0.0",
        purl=PackageURL(type=component_type, name=main_component_name, version='0.0.0')
    )
    
    # Set metadata for the BOM
    bom.metadata.tools.tools.add(Tool(name="bazel-dependency-sbom-generator", version="1.1.0"))
    bom.metadata.component = main_component
    
    # This is the index holder to make sure each bom_ref is unique
    true_index = 2
    for package, details in bazel_deps.items():
        package_name, version, purl_type = extract_package_info(details["tags"])
        
        if not package_name or not purl_type:
            print(f"Skipping package with invalid tags: {details['tags']}")
            continue
            
        try:
            purl = create_package_url(package_name, version, purl_type)
            bom_ref = f"{true_index}-{package_name}@{version}"
            
            component = Component(
                name=package_name,
                version=version,
                type=ComponentType.LIBRARY,
                bom_ref=bom_ref,
                purl=purl
            )
            
            bom.components.add(component)
            bom.register_dependency(main_component, [component])
            # Handle dependencies based on package type
            if purl_type == "pypi":
                is_valid = validate_package_name(package_name)
                if is_valid:
                    transitive_dependencies = get_package_versions(package_name)
                    if transitive_dependencies:
                        for dep_name, dep_version in transitive_dependencies:
                            dep_bom_ref = f"{true_index}-{dep_name}@{dep_version}"
                            dep_purl = create_package_url(dep_name, dep_version, "pypi")
                            
                            dep_component = Component(
                                name=dep_name,
                                version=dep_version,
                                type=ComponentType.LIBRARY,
                                bom_ref=dep_bom_ref,
                                purl=dep_purl
                            )
                            
                            bom.components.add(dep_component)
                            bom.register_dependency(main_component, [dep_component])
                            bom.register_dependency(component, [dep_component])
                            true_index += 1
            # if purl_type == "maven":
                
            
            # Register the component's dependencies
            bom.register_dependency(main_component, [component])
            true_index += 1
            
        except Exception as e:
            print(f"Error processing package {package_name}: {str(e)}")
            continue

    # Convert to JSON and validate
    json_outputter = JsonV1Dot6(bom)
    serialized_bom = json_outputter.output_as_string(indent=2)
    
    try:
        json_validator = JsonStrictValidator(SchemaVersion.V1_6)
        validation_errors = json_validator.validate_str(serialized_bom)
        if validation_errors:
            print('JSON invalid', 'ValidationError:', repr(validation_errors), sep='\n', file=sys.stderr)
            sys.exit(2)
        print('JSON valid')
    except MissingOptionalDependencyException as error:
        print('JSON-validation was skipped due to', error)
    
    # Reorder the JSON to have metadata at the top
    sbom_dict = json.loads(serialized_bom)
    ordered_dependencies = []
    for dep in sbom_dict.get("dependencies", []):
        ordered_dep = OrderedDict()
        ordered_dep["ref"] = dep["ref"]
        if "dependsOn" in dep:
            ordered_dep["dependsOn"] = dep["dependsOn"]
        ordered_dependencies.append(ordered_dep)

    ordered_sbom = OrderedDict([
        ("$schema", sbom_dict.get("$schema")),
        ("bomFormat", sbom_dict.get("bomFormat")),
        ("specVersion", sbom_dict.get("specVersion")),
        ("version", sbom_dict.get("version")),
        ("metadata", sbom_dict.get("metadata")),
        ("components", sbom_dict.get("components")),
        ("dependencies", ordered_dependencies),
    ])
    
    return ordered_sbom
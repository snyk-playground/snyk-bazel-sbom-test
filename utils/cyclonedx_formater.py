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

def generate_cyclonedx_sbom(bazel_deps):
    """
    Generate a CycloneDX SBOM from Bazel dependencies.

    Args:
        bazel_deps (dict): The Bazel dependencies.

    Returns:
        dict: A CycloneDX SBOM.
    """
    # Create a CycloneDX BOM object
    bom = Bom()
    
    # Define the main component of the project
    main_component = Component(
        name="project",
        version="0.0.0",
        type=ComponentType.APPLICATION,
        bom_ref="1-project@0.0.0",
        purl=PackageURL(type='pypi', name='project', version='0.0.0')
    )
    
    # Set metadata for the BOM
    bom.metadata.tools.tools.add(Tool(name="bazel-python-dependency-sbom-generator", version="1.0.0"))
    bom.metadata.component = main_component
    
    # This is the index holder to make sure each bom_ref is unique
    true_index = 2
    for index, (package, details) in enumerate(bazel_deps.items()):
        version = details["tags"][1].split('=')[1] if len(details["tags"]) > 1 else "unknown"
        package_name = details["tags"][0].split('=')[1] if len(details["tags"]) > 0 else package
        is_valid = False
        if validate_package_name(package_name):
            transitive_dependencies = get_package_versions(package_name)
            print(f"Here are the transitive dependencies: {transitive_dependencies}")
            if transitive_dependencies:
                is_valid = True
        else:
            print(f"Invalid package name: {package_name}  Skipping transitive dependency generation")
        
        # Construct a valid purl
        package_name_clean = package_name.lstrip('@').replace('//', '/')
        purl = None
        try:
            purl = PackageURL(type='pypi', name=package_name_clean, version=version if version != "unknown" else None)
        except ValueError as e:
            print(f"Invalid PURL for package {package_name_clean}: {e}")
        
        bom_ref = f"{true_index}-{package_name_clean}@{version}"
        component = Component(
            name=package_name_clean,
            version=version,
            type=ComponentType.LIBRARY,
            bom_ref=bom_ref,
            purl=purl  # Use the constructed purl if valid
        )
        bom.components.add(component)
        bom.register_dependency(main_component, [component])
        true_index += 1
        # Add dependencies to the CycloneDX BOM
        if is_valid:
            # Construct the dependsOn list as a string
            # depends_on = [f"{true_index}-{dep_name}@{dep_version}" for dep_name, dep_version in transitive_dependencies]
            for dep_name, dep_version in transitive_dependencies:
                transitive_component = Component(
                    name=dep_name,
                    version=dep_version,
                    type=ComponentType.LIBRARY,
                    bom_ref=f"{true_index}-{dep_name}@{dep_version}",
                    purl=PackageURL(type='pypi', name=dep_name, version=dep_version)
                )
                true_index += 1
                bom.components.add(transitive_component)
                bom.register_dependency(main_component, [transitive_component])
                bom.register_dependency(component, [transitive_component])
            # dependency = Dependency(ref=component.bom_ref, dependencies=depends_on_str)
            # bom.dependencies.add(dependency)
        else:
            dependency = Dependency(ref=component.bom_ref)
            bom.dependencies.add(dependency)
    
    # Use CycloneDX library to find transitive dependencies
    # This is a placeholder for actual transitive dependency resolution logic
    # You would need to implement this based on your specific requirements

    # Convert the CycloneDX BOM to JSON
    json_outputter: JsonV1Dot6 = JsonV1Dot6(bom)
    serialized_bom = json_outputter.output_as_string(indent=2)
    json_validator = JsonStrictValidator(SchemaVersion.V1_6)
    try:
        validation_errors = json_validator.validate_str(serialized_bom)
        if validation_errors:
            print('JSON invalid', 'ValidationError:', repr(validation_errors), sep='\n', file=sys.stderr)
            sys.exit(2)
        print('JSON valid')
    except MissingOptionalDependencyException as error:
        print('JSON-validation was skipped due to', error)
    # sbom_json = serialized_bom
    
    # Reorder the JSON to have metadata at the top
    sbom_dict = json.loads(serialized_bom)

    # Reorder the dependencies to have 'ref' before 'dependsOn'
    ordered_dependencies = []
    for dep in sbom_dict.get("dependencies", []):
        ordered_dep = OrderedDict()
        ordered_dep["ref"] = dep["ref"]
        if "dependsOn" in dep:
            ordered_dep["dependsOn"] = dep["dependsOn"]
        ordered_dependencies.append(ordered_dep)

    # Reconstruct the SBOM with ordered dependencies
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
import datetime
import pytz
import logging
from typing import Dict, List, Tuple, Optional, Any
from cyclonedx.model.bom import Bom
from cyclonedx.model.tool import Tool
from cyclonedx.model.component import Component, ComponentType, PackageURL
from cyclonedx.model.dependency import Dependency
# Note: Some imports may not be available in all versions
try:
    from cyclonedx.model.organization import OrganizationalEntity, OrganizationalContact
except ImportError:
    # Fallback for older versions
    OrganizationalEntity = None
    OrganizationalContact = None
from cyclonedx.output import make_outputter
from cyclonedx.output.json import JsonV1Dot6
from cyclonedx.schema import SchemaVersion, OutputFormat
from cyclonedx.validation.json import JsonStrictValidator
from cyclonedx.exception import MissingOptionalDependencyException
from collections import OrderedDict
import sys
import json
import re
import os
import platform

import pkg_resources

# Set up logging
logger = logging.getLogger(__name__)

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
    try:
        logger.debug(f"Determining component type for bazel_deps: {type(bazel_deps)}")
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
    except Exception as e:
        logger.error(f"Error determining component type: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return 'generic'

def _setup_enhanced_metadata(bom: Bom, main_component: Component, 
                           additional_metadata: Optional[Dict] = None) -> None:
    """
    Set up enhanced metadata for the BOM including Snyk-specific information.
    
    Args:
        bom (Bom): The CycloneDX BOM object
        main_component (Component): The main component
        additional_metadata (dict): Additional metadata to include
    """
    # Set the main component
    bom.metadata.component = main_component
    
    # Add tool information
    bom.metadata.tools.tools.add(Tool(
        name="bazel-dependency-sbom-generator", 
        version="2.0.0",
        vendor="Snyk"
    ))
    
    # Add Bazel tool information
    bom.metadata.tools.tools.add(Tool(
        name="bazel",
        version="latest"
    ))
    
    # Add timestamp
    bom.metadata.timestamp = datetime.datetime.now(pytz.UTC)
    
    # Add Snyk-specific metadata
    if additional_metadata:
        # Add organization information if provided
        if 'organization' in additional_metadata and OrganizationalEntity:
            org_info = additional_metadata['organization']
            try:
                bom.metadata.manufacture = OrganizationalEntity(
                    name=org_info.get('name', 'Unknown Organization'),
                    url=org_info.get('url'),
                    contact=OrganizationalContact(
                        name=org_info.get('contact_name'),
                        email=org_info.get('contact_email')
                    ) if org_info.get('contact_name') or org_info.get('contact_email') else None
                )
            except Exception as e:
                logger.warning(f"Could not set organization metadata: {e}")
        
        # Add project information
        if 'project' in additional_metadata:
            project_info = additional_metadata['project']
            bom.metadata.component.description = project_info.get('description')
            if project_info.get('url'):
                bom.metadata.component.external_references = [{
                    'type': 'website',
                    'url': project_info['url']
                }]
    
    # Add system information (properties are handled differently in CycloneDX)
    # Note: Properties might need to be added differently depending on the CycloneDX version
    try:
        from cyclonedx.model.property import Property
        properties = [
            Property(name="build.system", value="bazel"),
            Property(name="build.platform", value=platform.system()),
            Property(name="build.architecture", value=platform.machine()),
            Property(name="build.python.version", value=platform.python_version()),
            Property(name="snyk.sbom.version", value="2.0.0"),
            Property(name="snyk.sbom.generator", value="bazel-dependency-sbom-generator")
        ]
        bom.metadata.properties = properties
    except ImportError:
        # Fallback if Property class is not available
        logger.warning("Property class not available, skipping metadata properties")
    except Exception as e:
        logger.warning(f"Could not set metadata properties: {e}")



def generate_cyclonedx_sbom(bazel_deps: Dict, main_component_name: str = "project", 
                          project_version: str = "0.0.0", 
                          additional_metadata: Optional[Dict] = None) -> Dict:
    """
    Generate a CycloneDX SBOM from Bazel dependencies with enhanced metadata.

    Args:
        bazel_deps (dict): The Bazel dependencies.
        main_component_name (str): Name of the main component.
        project_version (str): Version of the main component.
        additional_metadata (dict): Additional metadata to include in the SBOM.

    Returns:
        dict: A CycloneDX SBOM with enhanced metadata.
    """
    logger.info(f"Generating CycloneDX SBOM for {main_component_name} v{project_version}")
    
    # Determine component type
    component_type = determine_component_type(bazel_deps)
    logger.info(f"Detected component type: {component_type}")
    
    # Create a CycloneDX BOM object
    bom = Bom()
    
    # Define the main component of the project
    main_component = Component(
        name=main_component_name,
        version=project_version,
        type=ComponentType.APPLICATION,
        bom_ref=f"1-{main_component_name}@{project_version}",
        purl=PackageURL(type=component_type, name=main_component_name, version=project_version)
    )
    
    # Enhanced metadata setup
    try:
        logger.debug("Setting up enhanced metadata")
        _setup_enhanced_metadata(bom, main_component, additional_metadata)
        logger.debug("Enhanced metadata setup completed")
    except Exception as e:
        logger.error(f"Error setting up enhanced metadata: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise
    
    # Process dependencies with enhanced error handling and logging
    true_index = 2
    processed_count = 0
    skipped_count = 0
    component_map = {}  # Map package names to components for dependency relationships
    
    # First pass: create all components
    for package, details in bazel_deps.items():
        try:
            logger.debug(f"Processing package: {package}, details: {details}")
            if not isinstance(details, dict) or "tags" not in details:
                logger.warning(f"Invalid details structure for package {package}: {details}")
                skipped_count += 1
                continue
            package_name, version, purl_type = extract_package_info(details["tags"])
            
            if not package_name or not purl_type:
                logger.warning(f"Skipping package with invalid tags: {details['tags']}")
                skipped_count += 1
                continue
                
            logger.debug(f"Processing {purl_type} package: {package_name}@{version}")
            
            purl = create_package_url(package_name, version, purl_type)
            bom_ref = f"{true_index}-{package_name}@{version}"
            
            component = Component(
                name=package_name,
                version=version,
                type=ComponentType.LIBRARY,
                bom_ref=bom_ref,
                purl=purl
            )
            
            # Add component to BOM and store in map
            bom.components.add(component)
            component_map[package] = component
            processed_count += 1
            
            true_index += 1
            
        except Exception as e:
            logger.error(f"Error processing package {package}: {str(e)}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            skipped_count += 1
            continue
    
    # Second pass: establish dependency relationships
    dependency_relationships = []
    for package, details in bazel_deps.items():
        if package not in component_map:
            continue
            
        component = component_map[package]
        dependencies = details.get('deps', [])
        
        if dependencies:
            # Find dependent components
            dependent_components = []
            for dep in dependencies:
                # Try to find the dependency in the component map
                # The dep might be in a different format (e.g., @pypi//markupsafe:pkg vs @@rules_python++pip+pypi_39_markupsafe//:pkg)
                found_dep = None
                
                # First try exact match
                if dep in component_map:
                    found_dep = component_map[dep]
                else:
                    # Try to find by package name extracted from the dep label
                    for comp_key, comp in component_map.items():
                        if comp.name in dep or dep.split('//')[-1].split(':')[0] in comp_key:
                            found_dep = comp
                            break
                
                if found_dep:
                    dependent_components.append(found_dep)
                    logger.debug(f"Found dependency: {dep} -> {found_dep.name}")
                else:
                    logger.debug(f"Dependency {dep} not found in component map")
            
            if dependent_components:
                dependency_relationships.append((component, dependent_components))
                logger.debug(f"Added dependency relationship: {component.name} -> {[c.name for c in dependent_components]}")
    
    # Register all dependency relationships
    for parent, children in dependency_relationships:
        bom.register_dependency(parent, children)
    
    # Register direct dependencies of main component
    # Find components that are not dependencies of other components
    all_dependent_components = set()
    for _, deps in dependency_relationships:
        all_dependent_components.update(deps)
    
    direct_deps = [comp for comp in component_map.values() 
                   if comp not in all_dependent_components]
    if direct_deps:
        bom.register_dependency(main_component, direct_deps)
    
    logger.info(f"Processed {processed_count} dependencies, skipped {skipped_count}")
    logger.info(f"Established {len(dependency_relationships)} dependency relationships")

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
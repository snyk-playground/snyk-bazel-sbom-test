import xml.etree.ElementTree as ET
import logging
from typing import Dict, Tuple, Optional, List

# Set up logging
logger = logging.getLogger(__name__)

def read_bazel_deps(file_path: str) -> Tuple[Dict, Optional[str]]:
    """
    Read and parse Bazel dependency XML file to extract dependencies and metadata.
    This function builds a proper dependency graph by following deps labels.
    
    Args:
        file_path (str): Path to the Bazel dependency XML file
        
    Returns:
        Tuple[Dict, Optional[str]]: Tuple containing (dependencies_dict, main_component_name)
    """
    try:
        logger.info(f"Reading Bazel dependencies from: {file_path}")
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        # Validate XML structure
        if root.tag != 'query':
            logger.warning(f"Unexpected root element: {root.tag}, expected 'query'")

        # First pass: collect all rules and find main component
        all_rules = {}
        main_component_name = None
        
        for rule in root.findall('rule'):
            rule_class = rule.get('class')
            rule_name = rule.get('name')
            
            if not rule_class or not rule_name:
                logger.warning(f"Skipping rule with missing class or name: {rule}")
                continue
                
            # Store all rules for dependency traversal
            all_rules[rule_name] = rule
            
            # Extract main component name from binary targets
            if rule_class in ["py_binary", "java_binary"]:
                name_element = rule.find('string[@name="name"]')
                if name_element is not None:
                    main_component_name = name_element.get('value')
                    logger.info(f"Found main component: {main_component_name} (type: {rule_class}, rule: {rule_name})")
        
        # Second pass: build dependency graph starting from main component
        result = {}
        if main_component_name:
            # Find the main component rule (look for the first binary rule we found)
            main_rule = None
            for rule_name, rule in all_rules.items():
                if rule.get('class') in ["py_binary", "java_binary"]:
                    name_element = rule.find('string[@name="name"]')
                    if name_element and name_element.get('value') == main_component_name:
                        main_rule = rule
                        logger.info(f"Found main component rule: {rule_name}")
                        break
            
            if main_rule:
                logger.info(f"Building dependency graph starting from {main_component_name}")
                _build_dependency_graph(main_rule, all_rules, result, set())
            else:
                logger.warning(f"Could not find main component rule for {main_component_name}, using fallback")
                # Fallback: collect all library dependencies
                for rule_name, rule in all_rules.items():
                    rule_class = rule.get('class')
                    if rule_class in ["py_library", "jvm_import", "maven_jar", "maven_import"]:
                        rule_info = _extract_rule_info(rule)
                        if rule_info:
                            result[rule_name] = rule_info
        else:
            logger.warning("No main component found, collecting all library dependencies")
            # Fallback: collect all library dependencies
            for rule_name, rule in all_rules.items():
                rule_class = rule.get('class')
                if rule_class in ["py_library", "jvm_import", "maven_jar", "maven_import"]:
                    rule_info = _extract_rule_info(rule)
                    if rule_info:
                        result[rule_name] = rule_info

        logger.info(f"Successfully parsed {len(result)} dependencies with transitive resolution")
        if not main_component_name:
            logger.warning("No main component found in the dependency graph")
            
    except ET.ParseError as e:
        logger.error(f"Error parsing XML file {file_path}: {e}")
        raise
    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error reading file {file_path}: {e}")
        raise

    return result, main_component_name

def _build_dependency_graph(rule: ET.Element, all_rules: Dict[str, ET.Element], 
                           result: Dict, visited: set) -> None:
    """
    Recursively build the dependency graph by traversing dependencies.
    
    Args:
        rule (ET.Element): Current rule to process
        all_rules (Dict[str, ET.Element]): All available rules in the XML
        result (Dict): Dictionary to store processed dependencies
        visited (set): Set of already visited rule names to prevent cycles
    """
    rule_name = rule.get('name')
    rule_class = rule.get('class')
    
    if not rule_name or rule_name in visited:
        return
        
    visited.add(rule_name)
    
    # Only process library rules (skip binary rules themselves)
    if rule_class in ["py_library", "jvm_import", "maven_jar", "maven_import"]:
        rule_info = _extract_rule_info(rule)
        if rule_info:
            result[rule_name] = rule_info
            logger.debug(f"Added dependency: {rule_name} (type: {rule_class})")
    
    # Process dependencies
    deps = rule.find('list[@name="deps"]')
    if deps is not None:
        for dep in deps.findall('label'):
            dep_value = dep.get('value')
            if dep_value and dep_value in all_rules:
                # Recursively process the dependency
                _build_dependency_graph(all_rules[dep_value], all_rules, result, visited)
            elif dep_value:
                logger.debug(f"Dependency {dep_value} not found in rules")

def _extract_rule_info(rule: ET.Element) -> Optional[Dict]:
    """
    Extract dependency information from a rule element.
    
    Args:
        rule (ET.Element): XML rule element
        
    Returns:
        Optional[Dict]: Dictionary containing dependency info or None if invalid
    """
    rule_name = rule.get('name')
    rule_info = {'deps': [], 'tags': [], 'rule_class': rule.get('class'), 'direct_deps': []}
    
    # Extract dependencies (these are the direct dependencies of this component)
    deps = rule.find('list[@name="deps"]')
    if deps is not None:
        for dep in deps.findall('label'):
            dep_value = dep.get('value')
            if dep_value:
                rule_info['deps'].append(dep_value)
                rule_info['direct_deps'].append(dep_value)
    
    # Extract tags (contains package coordinates)
    tags = rule.find('list[@name="tags"]')
    if tags is not None:
        for tag in tags.findall('string'):
            tag_value = tag.get('value')
            if tag_value:
                rule_info['tags'].append(tag_value)
    
    # Extract additional metadata
    _extract_additional_metadata(rule, rule_info)
    
    # Validate that we have meaningful information
    if not rule_info['tags'] and not rule_info['deps']:
        logger.warning(f"Rule {rule_name} has no tags or dependencies, skipping")
        return None
        
    return rule_info

def _extract_additional_metadata(rule: ET.Element, rule_info: Dict) -> None:
    """
    Extract additional metadata from rule elements.
    
    Args:
        rule (ET.Element): XML rule element
        rule_info (Dict): Dictionary to populate with metadata
    """
    # Extract location information
    location = rule.get('location')
    if location:
        rule_info['location'] = location
    
    # Extract generator information
    generator_name = rule.find('string[@name="generator_name"]')
    if generator_name is not None:
        rule_info['generator_name'] = generator_name.get('value')
        
    generator_function = rule.find('string[@name="generator_function"]')
    if generator_function is not None:
        rule_info['generator_function'] = generator_function.get('value')
    
    # Extract source files for Python rules
    srcs = rule.find('list[@name="srcs"]')
    if srcs is not None:
        rule_info['srcs'] = []
        for src in srcs.findall('label'):
            src_value = src.get('value')
            if src_value:
                rule_info['srcs'].append(src_value)

def validate_bazel_xml_structure(file_path: str) -> bool:
    """
    Validate that the XML file has the expected Bazel query structure.
    
    Args:
        file_path (str): Path to the XML file
        
    Returns:
        bool: True if valid, False otherwise
    """
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        # Check root element
        if root.tag != 'query':
            logger.error(f"Invalid root element: {root.tag}, expected 'query'")
            return False
            
        # Check for at least one rule element
        rules = root.findall('rule')
        if not rules:
            logger.error("No rule elements found in XML")
            return False
            
        # Check for valid rule structure
        for rule in rules[:5]:  # Check first 5 rules
            if not rule.get('class') or not rule.get('name'):
                logger.error("Found rule without class or name attribute")
                return False
                
        logger.info("XML structure validation passed")
        return True
        
    except ET.ParseError as e:
        logger.error(f"XML parsing error: {e}")
        return False
    except Exception as e:
        logger.error(f"Validation error: {e}")
        return False


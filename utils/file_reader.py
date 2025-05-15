import xml.etree.ElementTree as ET

def read_bazel_deps(file_path: str):
    result = {}
    main_component_name = None
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()

        for rule in root.findall('rule'):
            rule_class = rule.get('class')
            # Extract main component name
            if rule_class in ["py_binary", "java_binary"]:
                name_element = rule.find('string[@name="name"]')
                if name_element is not None:
                    main_component_name = name_element.get('value')
                    print(f"Main component name: {main_component_name}")
                    
            # Collect Maven dependencies
            if rule_class == "jvm_import":
                rule_name = rule.get('name')
                rule_info = {'deps': [], 'tags': []}
                
                # Extract dependencies
                deps = rule.find('list[@name="deps"]')
                if deps is not None:
                    for dep in deps.findall('label'):
                        rule_info['deps'].append(dep.get('value'))
                
                # Extract tags
                tags = rule.find('list[@name="tags"]')
                if tags is not None:
                    for tag in tags.findall('string'):
                        if tag.get('value').startswith('maven_coordinates='):
                            rule_info['tags'].append(tag.get('value'))
                        
                result[rule_name] = rule_info
            # Collect Python dependencies
            if rule_class == "py_library":
                rule_name = rule.get('name')
                rule_info = {'deps': [], 'tags': []}

                # Extract dependencies
                deps = rule.find('list[@name="deps"]')
                if deps is not None:
                    for dep in deps.findall('label'):
                        rule_info['deps'].append(dep.get('value'))

                # Extract tags
                tags = rule.find('list[@name="tags"]')
                if tags is not None:
                    for tag in tags.findall('string'):
                        rule_info['tags'].append(tag.get('value'))

                result[rule_name] = rule_info

    except ET.ParseError as e:
        print(f"Error parsing XML: {e}")
    except FileNotFoundError:
        print(f"File not found: {file_path}")

    return result, main_component_name


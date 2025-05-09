import typer
from utils.file_reader import read_bazel_deps  
from utils.cyclonedx_formater import generate_cyclonedx_sbom
from utils.file_writer import write_json_file
import json

app = typer.Typer()

def convert_bazel_depgraph_to_sbom(input_file: str, output_file: str):
    """
    Convert a Bazel dependency graph to an SBOM.
    
    Args:
        input_file (str): Path to the Bazel dependency graph file.
        output_file (str): Path where the SBOM will be saved.
    """
    print(f"Converting {input_file} to SBOM and saving to {output_file}")
    bazel_deps = read_bazel_deps(input_file)
    sbom = generate_cyclonedx_sbom(bazel_deps)
    write_json_file(output_file, sbom)
    print(f"SBOM saved to {output_file}")
    

@app.command()
def convert(input_file: str, output_file: str):
    """
    Command to convert a Bazel dependency graph to an SBOM.
    
    Args:
        input_file (str): Path to the Bazel dependency graph file.
        output_file (str): Path where the SBOM will be saved.
    """
    convert_bazel_depgraph_to_sbom(input_file, output_file)

if __name__ == "__main__":
    app()

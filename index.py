import typer
from utils.file_reader import read_bazel_deps  
from utils.cyclonedx_formater import generate_cyclonedx_sbom
from utils.file_writer import write_json_file
from utils.snyk_api import initiate_snyk_sbom_scan, get_snyk_sbom_scan_results, get_snyk_sbom_scan_status
import time
import sys
import json

app = typer.Typer()

def snyk_scan_status_poller(job_id: str, region: str, org_id: str):
    failed_status_check = False
    while True:
        status = get_snyk_sbom_scan_status(job_id, region, org_id)
        try:
            if status['data']['attributes']['status'] == 'completed':
                return status
        except KeyError:
            print(f"Error getting Snyk SBOM scan status: {status}.  Checking if results are present...")
            failed_status_check = True
        if failed_status_check:
            if status['data']['attributes']['sbom']['format'] == 'CycloneDX JSON':
                print(f"Snyk SBOM scan completed.  Results are present.")
                return status
        print(f"Snyk SBOM scan not completed yet.  Waiting for 30 seconds before checking again...")
        time.sleep(30)

def convert_bazel_depgraph_to_sbom(input_file: str, output_file: str):
    """
    Convert a Bazel dependency graph to an SBOM.
    
    Args:
        input_file (str): Path to the Bazel dependency graph file.
        output_file (str): Path where the SBOM will be saved.
    """
    print(f"Reading {input_file} to generate CycloneDX SBOM")
    bazel_deps, main_component_name = read_bazel_deps(input_file)
    print(f"Generating CycloneDX SBOM for {main_component_name}")
    sbom = generate_cyclonedx_sbom(bazel_deps, main_component_name)
    print(type(sbom))
    print(f"CycloneDX SBOM generated successfully.  Saving to {output_file}...")
    write_json_file(output_file, sbom)
    print(f"CycloneDX SBOM saved to {output_file}")
    return sbom

def run_snyk_scan(sbom: dict, command: str, region: str, org_id: str):
    """
    Run a Snyk scan on the given SBOM.
    
    Args:
        sbom (str): Path to the CycloneDX SBOM file.
        command (str): The command to run the Snyk scan with.
    """
    print(f"Running Snyk scan on sbom with command {command}")
    # Write logic to run the Snyk scan
    results = initiate_snyk_sbom_scan(sbom, org_id, region, command)
    job_id = results['data']['id']
    results = snyk_scan_status_poller(job_id, region, org_id)
    print(f"Snyk scan completed")
    
    return results
@app.command()
def convert_bazel_depgraph_to_sbom_and_run_snyk_scan(
    input_file: str = typer.Argument(
        ...,
        help="Path to the Bazel dependency graph XML file",
        exists=True
    ),
    output_file: str = typer.Argument(
        ...,
        help="Path where the CycloneDX SBOM JSON will be saved"
    ),
    snyk_scan_command: str = typer.Option(
        ...,
        "--scan-type", 
        "-s", 
        help="Run Snyk security scan: 'test' to run security test, 'monitor' for continuous monitoring (not supported)",
        case_sensitive=False
    ),
    region: str = typer.Option(
        "us.api.snyk.io",
        "--region", 
        "-r", 
        help="Snyk region"
    ),
    org_id: str = typer.Option(
        ...,
        "--org-id",
        "-org",
        help="Snyk organization ID"
    )
):

    sbom = convert_bazel_depgraph_to_sbom(input_file, output_file)
    if snyk_scan_command:
        if snyk_scan_command.lower() == 'test':
            results = run_snyk_scan(sbom, snyk_scan_command, region, org_id)
            print(json.dumps(results, indent=4))
        elif snyk_scan_command.lower() == 'monitor':
            typer.exit(1, "Monitoring is not supported")
        else:
            typer.exit(1, "Invalid command, please use 'test' or 'monitor'")

if __name__ == "__main__":
    app()

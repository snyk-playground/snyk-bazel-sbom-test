import typer
import logging
import sys
import json
import time
from pathlib import Path
from typing import Optional
from utils.file_reader import read_bazel_deps, validate_bazel_xml_structure
from utils.cyclonedx_formater import generate_cyclonedx_sbom
from utils.file_writer import write_json_file
from utils.snyk_api import initiate_snyk_sbom_scan, get_snyk_sbom_scan_results, get_snyk_sbom_scan_status

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('bazel_sbom_generator.log')
    ]
)
logger = logging.getLogger(__name__)

app = typer.Typer(
    name="bazel-sbom-generator",
    help="Generate CycloneDX SBOM from Bazel dependency files and send to Snyk for security scanning",
    add_completion=False
)

def snyk_scan_status_poller(job_id: str, region: str, org_id: str, max_wait_time: int = 1800) -> dict:
    """
    Poll Snyk scan status until completion or timeout.
    
    Args:
        job_id (str): Snyk job ID
        region (str): Snyk region
        org_id (str): Snyk organization ID
        max_wait_time (int): Maximum wait time in seconds (default: 30 minutes)
        
    Returns:
        dict: Final scan status
    """
    logger.info(f"Starting status polling for job {job_id}")
    start_time = time.time()
    failed_status_check = False
    poll_count = 0
    
    while True:
        poll_count += 1
        elapsed_time = time.time() - start_time
        
        if elapsed_time > max_wait_time:
            logger.error(f"Scan timeout after {max_wait_time} seconds")
            raise typer.Exit(1)
            
        try:
            status = get_snyk_sbom_scan_status(job_id, region, org_id)
            
            if status['data']['attributes']['status'] == 'completed':
                logger.info(f"Scan completed successfully after {poll_count} polls")
                return status
                
        except KeyError as e:
            logger.warning(f"Error getting scan status: {e}. Checking if results are present...")
            failed_status_check = True
            
        if failed_status_check:
            try:
                if status['data']['attributes']['sbom']['format'] == 'CycloneDX JSON':
                    logger.info("Snyk SBOM scan completed. Results are present.")
                    return status
            except KeyError:
                pass
                
        logger.info(f"Scan not completed yet (poll #{poll_count}, elapsed: {elapsed_time:.0f}s). Waiting 30 seconds...")
        time.sleep(30)

def convert_bazel_depgraph_to_sbom(input_file: str, output_file: str, 
                                  project_version: str = "0.0.0",
                                  additional_metadata: Optional[dict] = None) -> dict:
    """
    Convert a Bazel dependency graph to an SBOM with enhanced validation.
    
    Args:
        input_file (str): Path to the Bazel dependency graph file.
        output_file (str): Path where the SBOM will be saved.
        project_version (str): Version of the project.
        additional_metadata (dict): Additional metadata to include in the SBOM.
        
    Returns:
        dict: Generated CycloneDX SBOM
    """
    try:
        # Validate input file
        input_path = Path(input_file)
        if not input_path.exists():
            logger.error(f"Input file does not exist: {input_file}")
            raise typer.Exit(1)
            
        if not input_path.suffix.lower() == '.xml':
            logger.warning(f"Input file does not have .xml extension: {input_file}")
            
        # Validate XML structure
        logger.info(f"Validating XML structure for {input_file}")
        if not validate_bazel_xml_structure(input_file):
            logger.error("Invalid Bazel XML structure")
            raise typer.Exit(1)
            
        # Read and parse dependencies
        logger.info(f"Reading {input_file} to generate CycloneDX SBOM")
        bazel_deps, main_component_name = read_bazel_deps(input_file)
        
        if not bazel_deps:
            logger.error("No dependencies found in the input file")
            raise typer.Exit(1)
            
        if not main_component_name:
            main_component_name = "unknown-project"
            logger.warning("No main component name found, using 'unknown-project'")
            
        # Generate SBOM
        logger.info(f"Generating CycloneDX SBOM for {main_component_name} v{project_version}")
        sbom = generate_cyclonedx_sbom(
            bazel_deps, 
            main_component_name, 
            project_version,
            additional_metadata
        )
        
        # Save SBOM
        logger.info(f"Saving CycloneDX SBOM to {output_file}")
        write_json_file(output_file, sbom)
        logger.info(f"CycloneDX SBOM saved successfully to {output_file}")
        
        return sbom
        
    except Exception as e:
        logger.error(f"Error converting Bazel dependencies to SBOM: {str(e)}")
        raise typer.Exit(1)

def run_snyk_scan(sbom: dict, command: str, region: str, org_id: str, 
                  max_wait_time: int = 1800) -> dict:
    """
    Run a Snyk scan on the given SBOM with enhanced error handling.
    
    Args:
        sbom (dict): The CycloneDX SBOM dictionary.
        command (str): The Snyk scan command ('test' or 'monitor').
        region (str): Snyk region.
        org_id (str): Snyk organization ID.
        max_wait_time (int): Maximum wait time for scan completion.
        
    Returns:
        dict: Snyk scan results
    """
    try:
        logger.info(f"Initiating Snyk {command} scan for organization {org_id}")
        results = initiate_snyk_sbom_scan(sbom, org_id, region, command)
        
        if 'data' not in results or 'id' not in results['data']:
            logger.error("Invalid response from Snyk API")
            raise typer.Exit(1)
            
        job_id = results['data']['id']
        logger.info(f"Snyk scan initiated with job ID: {job_id}")
        
        # Poll for completion
        results = snyk_scan_status_poller(job_id, region, org_id, max_wait_time)
        logger.info("Snyk scan completed successfully")
        
        return results
        
    except Exception as e:
        logger.error(f"Error running Snyk scan: {str(e)}")
        raise typer.Exit(1)
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
        None,
        "--scan-type", 
        "-s", 
        help="Run Snyk security scan: 'test' to run security test, 'monitor' for continuous monitoring (not supported)",
        case_sensitive=False
    ),
    region: str = typer.Option(
        "us.api.snyk.io",
        "--region", 
        "-r", 
        help="Snyk region (default: us.api.snyk.io)"
    ),
    org_id: str = typer.Option(
        None,
        "--org-id",
        "-org",
        help="Snyk organization ID"
    ),
    project_version: str = typer.Option(
        "0.0.0",
        "--version",
        "-v",
        help="Project version (default: 0.0.0)"
    ),
    max_wait_time: int = typer.Option(
        1800,
        "--max-wait-time",
        "-w",
        help="Maximum wait time for Snyk scan completion in seconds (default: 1800)"
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        help="Enable verbose logging"
    ),
    no_scan: bool = typer.Option(
        False,
        "--no-scan",
        help="Generate SBOM only, skip Snyk scanning"
    )
):
    """
    Convert Bazel dependency graph to CycloneDX SBOM and optionally run Snyk security scan.
    
    This command processes a Bazel dependency XML file and generates a CycloneDX SBOM.
    Optionally, it can send the SBOM to Snyk for security scanning.
    
    Examples:
        # Generate SBOM only
        python index.py convert bazel_deps.xml output.json --no-scan
        
        # Generate SBOM and run Snyk test
        python index.py convert bazel_deps.xml output.json --scan-type test --org-id your-org-id
        
        # With custom version and verbose logging
        python index.py convert bazel_deps.xml output.json --version 1.2.3 --verbose --no-scan
    """
    # Set logging level based on verbose flag
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")
    
    try:
        # Prepare additional metadata
        additional_metadata = {
            "project": {
                "version": project_version,
                "description": f"Bazel project SBOM generated from {input_file}"
            }
        }
        
        # Convert to SBOM
        sbom = convert_bazel_depgraph_to_sbom(
            input_file, 
            output_file, 
            project_version,
            additional_metadata
        )
        
        # Run Snyk scan if requested
        if not no_scan and snyk_scan_command:
            if not org_id:
                typer.echo("--org-id is required when running Snyk scan", err=True)
                raise typer.Exit(1)
            if snyk_scan_command.lower() == 'test':
                logger.info("Starting Snyk security test scan")
                results = run_snyk_scan(sbom, snyk_scan_command, region, org_id, max_wait_time)
                typer.echo(json.dumps(results, indent=4))
            elif snyk_scan_command.lower() == 'monitor':
                typer.echo("Monitoring is not supported yet", err=True)
                raise typer.Exit(1)
            else:
                typer.echo(f"Invalid scan type: {snyk_scan_command}. Use 'test' or 'monitor'", err=True)
                raise typer.Exit(1)
        elif no_scan:
            logger.info("Skipping Snyk scan as requested")
            typer.echo(f"SBOM generated successfully: {output_file}")
        else:
            typer.echo("No scan type specified. Use --scan-type or --no-scan", err=True)
            raise typer.Exit(1)
            
    except typer.Exit:
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        typer.echo(f"Error: {str(e)}", err=True)
        raise typer.Exit(1)

@app.command()
def convert(
    input_file: str = typer.Argument(
        ...,
        help="Path to the Bazel dependency graph XML file",
        exists=True
    ),
    output_file: str = typer.Argument(
        ...,
        help="Path where the CycloneDX SBOM JSON will be saved"
    ),
    project_version: str = typer.Option(
        "0.0.0",
        "--version",
        "-v",
        help="Project version (default: 0.0.0)"
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        help="Enable verbose logging"
    )
):
    """
    Convert Bazel dependency graph to CycloneDX SBOM only (no Snyk scanning).
    
    This is a simplified command that only generates the SBOM without sending it to Snyk.
    
    Examples:
        # Basic conversion
        python index.py convert bazel_deps.xml output.json
        
        # With custom version
        python index.py convert bazel_deps.xml output.json --version 1.2.3
        
        # With verbose logging
        python index.py convert bazel_deps.xml output.json --verbose
    """
    # Set logging level based on verbose flag
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")
    
    try:
        # Prepare additional metadata
        additional_metadata = {
            "project": {
                "version": project_version,
                "description": f"Bazel project SBOM generated from {input_file}"
            }
        }
        
        # Convert to SBOM
        sbom = convert_bazel_depgraph_to_sbom(
            input_file, 
            output_file, 
            project_version,
            additional_metadata
        )
        
        typer.echo(f"✅ SBOM generated successfully: {output_file}")
        logger.info("SBOM generation completed successfully")
        
    except typer.Exit:
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        typer.echo(f"❌ Error: {str(e)}", err=True)
        raise typer.Exit(1)

if __name__ == "__main__":
    app()

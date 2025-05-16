import json
import requests
import sys
from requests.exceptions import HTTPError

from utils.helper import get_snyk_token

SNYK_TOKEN = get_snyk_token()

restHeaders = {'Content-Type': 'application/vnd.api+json', 'Authorization': f'token {SNYK_TOKEN}'}
restExportHeaders = {'Content-Type': 'application/json', 'Authorization': f'token {SNYK_TOKEN}'}
v1Headers = {'Content-Type': 'application/json; charset=utf-8', 'Authorization': f'token {SNYK_TOKEN}'}
rest_version = '2024-10-15'

def initiate_snyk_sbom_scan(sbom: dict, org_id: str, region: str, scan_type: str):
    if scan_type == 'test':
        url = f"https://{region}/rest/orgs/{org_id}/sbom_tests?version={rest_version}"
        body = {"data": {"type": "sbom_tests", "attributes": {"sbom": sbom}}}
        try:
            response = requests.post(url, headers=restHeaders, json=body)
            response.raise_for_status()
            return response.json()
        except HTTPError as e:
            print(f"Error initiating Snyk SBOM {scan_type} scan: {e}")
            sys.exit(1)
    if scan_type == 'monitor':
        print("Snyk monitor is not supported yet")
        #url = f"https://snyk.io/api/v1/org/{org_id}/project/{project_id}/monitor/cyclonedx"

def get_snyk_sbom_scan_results(job_id: str, region: str, org_id: str):
    url = f"https://{region}/rest/orgs/{org_id}/sbom_tests/{job_id}/results?version={rest_version}"
    try:
        response = requests.get(url, headers=restHeaders)
        response.raise_for_status()
        return response.json()
    except HTTPError as e:
        print(f"Error getting Snyk SBOM scan results: {e}")
        sys.exit(1)

def get_snyk_sbom_scan_status(job_id: str, region: str, org_id: str):
    url = f"https://{region}/rest/orgs/{org_id}/sbom_tests/{job_id}?version={rest_version}"
    try:
        response = requests.get(url, headers=restHeaders)
        response.raise_for_status()
        return response.json()
    except HTTPError as e:
        print(f"Error getting Snyk SBOM scan status: {e}")
        sys.exit(1)
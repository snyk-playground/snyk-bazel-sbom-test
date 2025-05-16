import os
import re
import sys

def get_snyk_token():
    SNYK_TOKEN = check_if_snyk_token_exist()
    
    pattern = re.compile(r'([\d\w]{8}-[\d\w]{4}-[\d\w]{4}-[\d\w]{4}-[\d\w]{12})')
    if pattern.fullmatch(SNYK_TOKEN) == None:
        print("Snyk token is not defined or not valid.")
        sys.exit()
    else:
        return SNYK_TOKEN

def check_if_snyk_token_exist():
    print("Checking for Snyk token environment variable")
    try:
        if os.environ.get('SNYK_TOKEN'):
            print("Found snyk token")
            return os.getenv('SNYK_TOKEN')
    except:
        print("Snyk token does not exist")
        sys.exit()
import requests
import argparse
from requests.auth import HTTPBasicAuth

def parse_arguments():
    parser = argparse.ArgumentParser(description='Query OpenSearch security settings using Basic Auth.')
    parser.add_argument('--endpoint', required=True, help='OpenSearch cluster endpoint, e.g., http://localhost:9200')
    parser.add_argument('--username', required=True, help='Username for Basic Authentication')
    parser.add_argument('--password', required=True, help='Password for Basic Authentication')
    return parser.parse_args()

def get_user_info(endpoint, username, password):
    url = f'{endpoint}/_security/user/_me'
    response = requests.get(url, auth=HTTPBasicAuth(username, password))
    return response.json()

def get_role_info(endpoint, username, password, role_name):
    url = f'{endpoint}/_security/role/{role_name}'
    response = requests.get(url, auth=HTTPBasicAuth(username, password))
    return response.json()

def main():
    args = parse_arguments()
    endpoint = args.endpoint
    username = args.username
    password = args.password

    # Get and print user info
    user_info = get_user_info(endpoint, username, password)
    print("User Info:", user_info)

    # Get and print role info for each role associated with the user
    if 'roles' in user_info:
        for role in user_info['roles']:
            role_info = get_role_info(endpoint, username, password, role)
            print(f"Role {role} Info:", role_info)

if __name__ == '__main__':
    main()

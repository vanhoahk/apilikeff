import requests
import random

# Define the API URL
API_URL = 'https://hasaki.io.vn/tests/test.php'

def load():
    # No need for database connection, we will fetch from API
    pass

def fetch_accounts_from_api():
    response = requests.get(API_URL)
    if response.status_code == 200:
        # Assuming the API returns a JSON array of accounts
        return response.json()
    else:
        print(f"Error fetching data from API: {response.status_code}")
        return []

def get_random_accounts(n=101):
    accounts = fetch_accounts_from_api()
    if accounts:  # Ensure accounts is not empty
        if len(accounts) > n:
            accounts = random.sample(accounts, n)
        return accounts
    return []

def get_random_account(n=2):
    accounts = fetch_accounts_from_api()
    if accounts:  # Ensure accounts is not empty
        if len(accounts) > n:
            accounts = random.sample(accounts, n)
        return accounts
    return []

def delete_account_by_id(account_id):
    # For deleting an account, assuming the API supports it
    delete_url = f"{API_URL}/delete/{account_id}"  # Update this URL based on your API specification
    response = requests.delete(delete_url)
    if response.status_code == 200:
        print(f"Account {account_id} deleted successfully.")
    else:
        print(f"Error deleting account: {response.status_code}")

# Example usage for getting random accounts

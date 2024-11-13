import requests

def run(base_url):
    """
    Simulates a Broken Access Control scanner. This function tests access to 
    protected endpoints without proper authorization to detect potential flaws.
    :param base_url: The domain to scan.
    """
    # Endpoints to test (modify based on your application's structure)
    endpoints_to_check = [
        "/admin/dashboard",
        "/user/settings",
        "/api/secure-data"
    ]
    
    results = []
    for endpoint in endpoints_to_check:
        try:
            url = f"{base_url}{endpoint}"
            response = requests.get(url)

            # Check for unrestricted access (HTTP 200 OK) when it shouldn't be accessible
            if response.status_code == 200:
                results.append({
                    'endpoint': endpoint,
                    'status': 'Vulnerable',
                    'details': 'Endpoint accessible without proper authentication'
                })
            else:
                results.append({
                    'endpoint': endpoint,
                    'status': 'Secure',
                    'details': f'Status code: {response.status_code}'
                })
        except Exception as e:
            results.append({
                'endpoint': endpoint,
                'status': 'Error',
                'details': str(e)
            })

    return results

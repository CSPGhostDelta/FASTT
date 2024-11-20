import requests
import urllib3
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def run(base_url):
    try:
        parsed_url = urlparse(base_url)
        if not parsed_url.scheme:
            base_url = f"https://{base_url}"
    except Exception as parse_error:
        return [{
            'url': base_url,
            'endpoint': 'URL Parsing',
            'details': f'Invalid URL: {str(parse_error)}',
            'vulnerability_status': 'Error'
        }]
    

    endpoints_to_check = [
        "/admin/dashboard",
        "/user/settings",
        "/api/secure-data",
        "/score-board"
    ]
    
    results = []
    
    headers_list = [
        {}, 
        {'User-Agent': 'Mozilla/5.0'}, 
        {'Authorization': 'Bearer invalid_token'} 
    ]
    
    for endpoint in endpoints_to_check:
        endpoint_results = []
        
        for headers in headers_list:
            try:
                url = f"{base_url.rstrip('/')}{endpoint}"
                
                response = requests.get(
                    url, 
                    headers=headers, 
                    timeout=10, 
                    verify=False 
                )
                
                result = {
                    'url': url,
                    'endpoint': endpoint,
                    'headers_used': list(headers.keys()),
                    'status_code': response.status_code
                }
                
                if response.status_code == 200:
                    result.update({
                        'details': 'Endpoint potentially accessible without proper authentication',
                        'vulnerability_status': 'Vulnerable'
                    })
                elif 300 <= response.status_code < 400:
                    result.update({
                        'details': 'Potential redirection detected',
                        'vulnerability_status': 'Potential'
                    })
                else:
                    result.update({
                        'details': f'Endpoint protected. Status code: {response.status_code}',
                        'vulnerability_status': 'Secure'
                    })
                
                endpoint_results.append(result)
            
            except requests.exceptions.RequestException as e:
                endpoint_results.append({
                    'url': url,
                    'endpoint': endpoint,
                    'headers_used': list(headers.keys()),
                    'details': f'Request Error: {str(e)}',
                    'vulnerability_status': 'Error'
                })
            except Exception as e:
                endpoint_results.append({
                    'url': url,
                    'endpoint': endpoint,
                    'headers_used': list(headers.keys()),
                    'details': f'Unexpected Error: {str(e)}',
                    'vulnerability_status': 'Error'
                })
        
        results.extend(endpoint_results)
    
    return results
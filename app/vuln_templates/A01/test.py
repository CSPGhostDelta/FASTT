SCAN_TEMPLATE = {
    'info': {
        'name': 'Admin Page Access Control Check',
        'type': 'Broken Access Control',
        'severity': 'High',
        'description': 'Checks for broken access control on the admin page by attempting unauthorized access.',
        'cvss_score': '7.5',
        'cvss_metrics': 'AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H',
        'cwe_code': '287',
        'cve_code': 'CVE-2021-12345',
        'full_description': 'This vulnerability exists when an attacker can access restricted areas, such as admin pages, without proper authentication or authorization.',
        'remediation': 'Ensure that proper access controls are implemented on the admin page. Only authorized users should be able to access it.',
    },
    'entry_point': {
        'entry_point_method': 'path', 
        'paths': [
            '{domain}', 
        ],
    },
    'payloads': {
        'payload_type': 'single',
        'payload': [
            'admin'
        ],
    },
}

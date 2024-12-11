SCAN_TEMPLATE = {
    'info': {
        'name': 'ActiveAdmin Admin Dashboard',
        'severity': 'Informational',
        'description': 'Discovers potential broken admin paths on a target domain.',
        'cvss_score': '4.0',
        'cvss_metrics': '',
        'payloads': {
            'payload_type': 'single',
            'payload': [ 
                '/dashboard'
            ]
        },
        'full_description': '', 
        'remediation': 'Secure the /admin path and enforce strict authentication measures.',
        'type': 'Broken Access Control',
        'matcher': '',
        'cwe_code': '',
        'cve_code': ''
    }
}

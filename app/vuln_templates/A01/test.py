# app/vuln_templates/A01/test.py

SCAN_TEMPLATE = {
    'info': {
        'name': 'Example Vulnerability',
        'type': 'Example Type',
        'severity': 'Medium',
        'description': 'This is an example vulnerability for testing.',
        'cvss_score': '5.0',
        'cvss_metrics': 'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
        'cwe_code': '123',  # Example CWE code
        'cve_code': 'CVE-2024-XXXX',  # Example CVE code
        'full_description': 'Detailed description of the example vulnerability.',
        'remediation': 'Remediation steps for the example vulnerability.',
    },

    'entry_point': {
        'entry_point_method': 'path',  # This defines the type of vulnerability (header, parameter, or path).
        'paths': [
            '{domain}/',  # Example path to check
        ]
    },

    'payloads': {
        'payload_type': 'single',  # or 'wordlist' choose one of them.
        'payload': [
            'admin ',  # Example payload for testing
        ]
    },

    'execute': "$entry_point, $payloads"  # Keeping execute as a string
}
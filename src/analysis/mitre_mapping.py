
MITRE_RULES = [
    {
        "keywords": ["login failed", "failed login"],
        "technique_id": "T1110",
        "technique_name": "Brute Force"
    },
    {
        "keywords": ["login successful"],
        "technique_id": "T1078",
        "technique_name": "Valid Accounts"
    },
    {
        "keywords": ["suspicious powershell", "powershell process"],
        "technique_id": "T1059.001",
        "technique_name": "PowerShell"
    },
    {
        "keywords": ["outbound network connection"],
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol"
    }
]


def map_mitre_technique(description):
    """Map an event description to a MITRE ATT&CK technique."""

    text = description.lower()

    for rule in MITRE_RULES:
        if any(keyword in text for keyword in rule["keywords"]):
            return (
                f'{rule["technique_id"]} - '
                f'{rule["technique_name"]}'
            )

    return None
"""Shared fixture dicts for Phase 3 tests.

These match the BusinessCardJson shape from .cursor/docs/1-interface-contract.md §F
exactly. Import them directly in test files or via the conftest.py fixtures.
"""

# Fully-populated card — Jamie Park (interface contract §F)
JAMIE_PARK: dict = {
    "validationStatus": "VALID",
    "validationMessage": "",
    "full_name": "Jamie Park",
    "first_name": "Jamie",
    "last_name": "Park",
    "prefix": None,
    "suffix": None,
    "title": "Senior Designer",
    "organization": "Helio Studio",
    "department": "Brand & Experience",
    "phones": [
        {"number": "(415) 555-0182", "type": "WORK"},
        {"number": "+1-415-555-0199", "type": "MOBILE"},
    ],
    "emails": [
        {"address": "jamie@heliostudio.co", "type": "WORK"},
        {"address": "jamie.park@gmail.com", "type": "PERSONAL"},
    ],
    "urls": [
        "https://heliostudio.co",
        "https://jamiepark.design",
    ],
    "address": {
        "street": "340 Pine Street",
        "street2": "Suite 800",
        "city": "San Francisco",
        "state": "CA",
        "postal_code": "94104",
        "country": "USA",
    },
    "linkedin": "linkedin.com/in/jamiepark",
    "twitter": "@jamiepark",
    "instagram": "@heliostudio",
    "note": "Pronouns: they/them",
}

# Minimal card — Chris Okafor (interface contract §F)
CHRIS_OKAFOR: dict = {
    "validationStatus": "VALID",
    "validationMessage": "",
    "full_name": "Chris Okafor",
    "first_name": "Chris",
    "last_name": "Okafor",
    "prefix": None,
    "suffix": None,
    "title": None,
    "organization": None,
    "department": None,
    "phones": [
        {"number": "212-555-0147", "type": "WORK"},
    ],
    "emails": [],
    "urls": [],
    "address": None,
    "linkedin": None,
    "twitter": None,
    "instagram": None,
    "note": None,
}

# All-null card — every scalar None, every array empty
ALL_NULL: dict = {
    "validationStatus": "VALID",
    "validationMessage": "",
    "full_name": None,
    "first_name": None,
    "last_name": None,
    "prefix": None,
    "suffix": None,
    "title": None,
    "organization": None,
    "department": None,
    "phones": [],
    "emails": [],
    "urls": [],
    "address": None,
    "linkedin": None,
    "twitter": None,
    "instagram": None,
    "note": None,
}

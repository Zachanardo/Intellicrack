"""Common license response templates for network interception."""

def get_adobe_response_templates():
    """Get Adobe Creative Cloud response templates."""
    return {
        'json': {
            'status': 'SUCCESS',
            'message': 'License is valid',
            'expiry': '2099-12-31',
            'serial': '1234-5678-9012-3456-7890',
            'valid': True,
            'activated': True,
            'expired': False,
            'products': [
                {'id': 'PHSP', 'name': 'Photoshop', 'status': 'ACTIVATED'},
                {'id': 'ILST', 'name': 'Illustrator', 'status': 'ACTIVATED'},
                {'id': 'AEFT', 'name': 'After Effects', 'status': 'ACTIVATED'}
            ]
        },
        'xml': """
            <response>
                <status>SUCCESS</status>
                <license>
                    <valid>true</valid>
                    <expired>false</expired>
                    <expiry>2099-12-31</expiry>
                    <serial>1234-5678-9012-3456-7890</serial>
                </license>
            </response>
        """
    }

def get_autodesk_response_templates():
    """Get Autodesk response templates."""
    return {
        'json': {
            'status': 'success',
            'license': {
                'status': 'ACTIVATED',
                'type': 'PERMANENT',
                'expiry': '2099-12-31'
            },
            'user': {
                'name': 'Licensed User',
                'email': 'user@example.com',
                'type': 'PREMIUM'
            },
            'products': [
                {'id': 'AUTOCAD', 'name': 'AutoCAD', 'status': 'ACTIVATED'},
                {'id': '3DSMAX', 'name': '3ds Max', 'status': 'ACTIVATED'},
                {'id': 'REVIT', 'name': 'Revit', 'status': 'ACTIVATED'}
            ]
        }
    }

def get_jetbrains_response_templates():
    """Get JetBrains response templates."""
    return {
        'json': {
            'licenseId': '1234567890',
            'licenseType': 'commercial',
            'evaluationLicense': False,
            'expired': False,
            'perpetualLicense': True,
            'errorCode': 0,
            'errorMessage': None,
            'licenseExpirationDate': '2099-12-31',
            'licenseExpirationDateMs': 4102444800000,
            'products': [
                {'code': 'II', 'name': 'IntelliJ IDEA', 'status': 'ACTIVATED'},
                {'code': 'PS', 'name': 'PhpStorm', 'status': 'ACTIVATED'},
                {'code': 'WS', 'name': 'WebStorm', 'status': 'ACTIVATED'}
            ]
        }
    }

def get_microsoft_response_templates():
    """Get Microsoft response templates."""
    return {
        'json': {
            'status': 'licensed',
            'licenseStatus': 'licensed',
            'gracePeriodDays': 0,
            'errorCode': 0,
            'errorMessage': None,
            'products': [
                {'id': 'O365', 'name': 'Office 365', 'status': 'ACTIVATED'},
                {'id': 'WINPRO', 'name': 'Windows 10 Pro', 'status': 'ACTIVATED'},
                {'id': 'VISIO', 'name': 'Visio', 'status': 'ACTIVATED'}
            ]
        }
    }

def get_generic_response_templates():
    """Get generic response templates."""
    return {
        'json': {
            'status': 'success',
            'license': 'valid',
            'expiry': '2099-12-31',
            'message': 'License is valid'
        },
        'xml': """
            <response>
                <status>success</status>
                <license>valid</license>
                <expiry>2099-12-31</expiry>
                <message>License is valid</message>
            </response>
        """
    }

def get_all_response_templates():
    """Get all response templates organized by service."""
    return {
        'adobe': get_adobe_response_templates(),
        'autodesk': get_autodesk_response_templates(),
        'jetbrains': get_jetbrains_response_templates(),
        'microsoft': get_microsoft_response_templates(),
        'generic': get_generic_response_templates()
    }
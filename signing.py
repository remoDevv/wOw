# Previous code remains the same until generate_manifest method
# Only updating the generate_manifest method at the end of the file

    @staticmethod
    def generate_manifest(bundle_id, app_url, title, icon_url=None, full_size_icon_url=None, version='1.0'):
        """Generate manifest file for OTA installation"""
        manifest = {
            'items': [{
                'assets': [{
                    'kind': 'software-package',
                    'url': app_url
                }],
                'metadata': {
                    'bundle-identifier': bundle_id,
                    'bundle-version': version,
                    'kind': 'software',
                    'platform-identifier': 'ios',
                    'title': title
                }
            }]
        }
        
        return plistlib.dumps(manifest)

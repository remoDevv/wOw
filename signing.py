import os
import tempfile
import shutil
import subprocess
import plistlib
from werkzeug.utils import secure_filename

class IPASigner:
    def __init__(self, app_path, p12_path, provision_path, p12_password):
        self.app_path = app_path
        self.p12_path = p12_path
        self.provision_path = provision_path
        self.p12_password = p12_password

    def get_cert_info(self):
        try:
            # Import certificate to keychain
            cmd = [
                'security', 'import', self.p12_path,
                '-P', self.p12_password,
                '-k', '/tmp/login.keychain',
                '-T', '/usr/bin/codesign'
            ]
            subprocess.run(cmd, check=True, capture_output=True)
            
            # Get certificate info
            cmd = ['security', 'find-identity', '-p', 'codesign', '-v']
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            
            # Extract certificate ID from output
            for line in result.stdout.split('\n'):
                if 'iPhone Developer' in line or 'iPhone Distribution' in line:
                    return line.split('"')[1]
            raise Exception('No valid iOS signing certificate found')
        except Exception as e:
            raise Exception(f'Failed to process certificate: {str(e)}')

    def extract_bundle_id(self):
        try:
            with open(self.provision_path, 'rb') as f:
                content = f.read()
                start = content.find(b'<?xml')
                end = content.find(b'</plist>') + 8
                plist_data = plistlib.loads(content[start:end])
                return plist_data['Entitlements']['application-identifier'].split('.', 1)[1]
        except Exception as e:
            raise Exception(f'Failed to extract bundle ID: {str(e)}')

    def sign_ipa(self):
        temp_dir = None
        try:
            temp_dir = tempfile.mkdtemp()
            
            # Extract IPA
            ipa_extract_path = os.path.join(temp_dir, 'ipa_contents')
            os.makedirs(ipa_extract_path)
            subprocess.run(['unzip', '-q', self.app_path, '-d', ipa_extract_path], check=True)
            
            # Find .app directory
            app_dir = None
            for root, dirs, _ in os.walk(os.path.join(ipa_extract_path, 'Payload')):
                for dir in dirs:
                    if dir.endswith('.app'):
                        app_dir = os.path.join(root, dir)
                        break
                if app_dir:
                    break
                    
            if not app_dir:
                raise Exception('No .app bundle found in IPA')
                
            # Copy provisioning profile
            prov_dest = os.path.join(app_dir, 'embedded.mobileprovision')
            shutil.copy2(self.provision_path, prov_dest)
            
            # Get signing certificate
            signing_identity = self.get_cert_info()
            
            # Sign the app
            subprocess.run([
                'codesign',
                '--force',
                '--sign', signing_identity,
                '--entitlements', self.provision_path,
                app_dir
            ], check=True)
            
            # Create output path
            output_filename = 'signed_' + secure_filename(os.path.basename(self.app_path))
            output_path = os.path.join(os.path.dirname(self.app_path), output_filename)
            
            # Create new IPA
            subprocess.run([
                'cd', ipa_extract_path, '&&',
                'zip', '-qr', output_path, 'Payload'
            ], shell=True, check=True)
            
            return True, output_path
            
        except Exception as e:
            return False, str(e)
            
        finally:
            # Cleanup
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)

    @staticmethod
    def generate_manifest(bundle_id, app_url, title, version='1.0'):
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

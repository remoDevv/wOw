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
            # Extract certificate info using OpenSSL
            cmd = [
                'openssl', 'pkcs12',
                '-in', self.p12_path,
                '-passin', f'pass:{self.p12_password}',
                '-nokeys',
                '-clcerts'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            # Extract subject name from certificate
            subject_cmd = [
                'openssl', 'x509',
                '-noout',
                '-subject'
            ]
            subject = subprocess.run(
                subject_cmd,
                input=result.stdout,
                capture_output=True,
                text=True,
                check=True
            )
            
            if 'iPhone' not in subject.stdout:
                raise Exception('No valid iOS signing certificate found')
                
            return subject.stdout.strip()
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
            # Validate input files
            if not os.path.exists(self.app_path) or not self.app_path.endswith('.ipa'):
                raise ValueError('Invalid IPA file')
            if not os.path.exists(self.p12_path) or not self.p12_path.endswith('.p12'):
                raise ValueError('Invalid P12 certificate')
            if not os.path.exists(self.provision_path) or not self.provision_path.endswith('.mobileprovision'):
                raise ValueError('Invalid provisioning profile')

            temp_dir = tempfile.mkdtemp()
            ipa_extract_path = os.path.join(temp_dir, 'ipa_contents')
            os.makedirs(ipa_extract_path)

            # Extract IPA
            try:
                subprocess.run(['unzip', '-q', self.app_path, '-d', ipa_extract_path], check=True)
            except subprocess.CalledProcessError:
                raise ValueError('Failed to extract IPA file')

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
                raise ValueError('No .app bundle found in IPA')

            # Copy provisioning profile
            prov_dest = os.path.join(app_dir, 'embedded.mobileprovision')
            shutil.copy2(self.provision_path, prov_dest)

            # Get signing certificate and verify
            try:
                signing_identity = self.get_cert_info()
            except Exception as e:
                raise ValueError(f'Certificate validation failed: {str(e)}')

            try:
                # Extract private key
                key_path = os.path.join(temp_dir, 'private.key')
                subprocess.run([
                    'openssl', 'pkcs12',
                    '-in', self.p12_path,
                    '-passin', f'pass:{self.p12_password}',
                    '-nocerts',
                    '-out', key_path
                ], check=True)
                
                # Sign using OpenSSL
                subprocess.run([
                    'openssl', 'cms',
                    '-sign',
                    '-binary',
                    '-in', app_dir,
                    '-signer', self.p12_path,
                    '-inkey', key_path,
                    '-outform', 'DER',
                    '-out', os.path.join(app_dir, 'signature')
                ], check=True)
            except subprocess.CalledProcessError as e:
                raise ValueError(f'Code signing failed: {e.stderr}')

            # Create output path
            output_filename = 'signed_' + secure_filename(os.path.basename(self.app_path))
            output_path = os.path.join(os.path.dirname(self.app_path), output_filename)

            # Create new IPA
            try:
                subprocess.run([
                    'cd', ipa_extract_path, '&&',
                    'zip', '-qr', output_path, 'Payload'
                ], shell=True, check=True)
            except subprocess.CalledProcessError:
                raise ValueError('Failed to create signed IPA')

            return True, output_path

        except Exception as e:
            return False, str(e)

        finally:
            # Cleanup
            if temp_dir and os.path.exists(temp_dir):
                try:
                    shutil.rmtree(temp_dir)
                    if os.path.exists(key_path):
                        os.remove(key_path)
                except:
                    pass  # Ignore cleanup errors

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

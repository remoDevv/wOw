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
        self.temp_dir = None
        self.key_path = None

    def cleanup(self):
        """Clean up temporary files and directories"""
        try:
            if self.key_path and os.path.exists(self.key_path):
                os.remove(self.key_path)
            if self.temp_dir and os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
        except Exception as e:
            print(f"Warning: Cleanup failed: {str(e)}")

    def get_cert_info(self):
        try:
            # Extract certificate info using OpenSSL
            process = subprocess.run([
                'openssl', 'pkcs12',
                '-in', self.p12_path,
                '-passin', f'pass:{self.p12_password}',
                '-nokeys',
                '-info'
            ], capture_output=True, text=True, check=True)
            
            if 'iPhone' not in process.stdout and 'iOS' not in process.stdout:
                raise ValueError('Not a valid iOS signing certificate')
                
            return process.stdout
        except subprocess.CalledProcessError as e:
            raise ValueError(f'Failed to read certificate: {e.stderr}')

    def extract_bundle_id(self):
        """Extract bundle ID from provisioning profile"""
        try:
            with open(self.provision_path, 'rb') as f:
                content = f.read()
                start = content.find(b'<?xml')
                end = content.find(b'</plist>') + 8
                if start == -1 or end == 7:
                    raise ValueError('Invalid provisioning profile format')
                
                plist_data = plistlib.loads(content[start:end])
                app_id = plist_data.get('Entitlements', {}).get('application-identifier', '')
                if not app_id:
                    raise ValueError('No application identifier found in profile')
                
                return app_id.split('.')[-1]
        except Exception as e:
            raise ValueError(f'Failed to extract bundle ID: {str(e)}')

    def extract_private_key(self):
        """Extract private key from P12 certificate"""
        try:
            if self.temp_dir is None:
                self.temp_dir = tempfile.mkdtemp()
            self.key_path = os.path.join(self.temp_dir, 'private.key')
            subprocess.run([
                'openssl', 'pkcs12',
                '-in', self.p12_path,
                '-passin', f'pass:{self.p12_password}',
                '-nocerts',
                '-nodes',
                '-out', self.key_path
            ], check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError as e:
            raise ValueError(f'Failed to extract private key: {e.stderr}')

    @staticmethod
    def is_binary_file(file_path):
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                return b'\x00' in chunk
        except Exception:
            return False

    def sign_binary(self, file_path):
        try:
            # Try using ldid if available
            try:
                subprocess.run(['ldid', '-S', file_path], check=True, capture_output=True)
                return True
            except (subprocess.CalledProcessError, FileNotFoundError):
                # Fall back to OpenSSL signing
                sig_path = file_path + '.sig'
                subprocess.run([
                    'openssl', 'cms',
                    '-sign', '-binary',
                    '-in', file_path,
                    '-signer', self.p12_path,
                    '-inkey', self.key_path,
                    '-certfile', self.provision_path,
                    '-outform', 'DER',
                    '-out', sig_path
                ], check=True, capture_output=True)
                return True
        except Exception as e:
            print(f"Warning: Failed to sign binary {file_path}: {str(e)}")
            return False

    def sign_ipa(self):
        """Sign IPA file using OpenSSL"""
        try:
            # Input validation
            if not all(os.path.exists(p) for p in [self.app_path, self.p12_path, self.provision_path]):
                raise ValueError('One or more input files do not exist')
            if not self.app_path.endswith('.ipa'):
                raise ValueError('Invalid IPA file')

            # Create temporary directory
            self.temp_dir = tempfile.mkdtemp()
            ipa_extract_path = os.path.join(self.temp_dir, 'ipa_contents')
            os.makedirs(ipa_extract_path)

            # Extract IPA
            try:
                subprocess.run([
                    'unzip', '-qq', self.app_path, '-d', ipa_extract_path
                ], check=True, capture_output=True)
            except subprocess.CalledProcessError as e:
                raise ValueError(f'Failed to extract IPA: {e.stderr}')

            # Find .app directory
            payload_path = os.path.join(ipa_extract_path, 'Payload')
            if not os.path.exists(payload_path):
                raise ValueError('Invalid IPA structure: No Payload directory')
            
            app_dir = None
            for item in os.listdir(payload_path):
                if item.endswith('.app'):
                    app_dir = os.path.join(payload_path, item)
                    break
            if not app_dir:
                raise ValueError('No .app bundle found in IPA')

            # Verify certificate and extract private key
            self.get_cert_info()
            self.extract_private_key()

            # Copy provisioning profile
            shutil.copy2(self.provision_path, os.path.join(app_dir, 'embedded.mobileprovision'))

            # Sign the application binaries
            signed_count = 0
            for root, _, files in os.walk(app_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    if self.is_binary_file(file_path):
                        if self.sign_binary(file_path):
                            signed_count += 1

            if signed_count == 0:
                print("Warning: No binary files were signed")
            else:
                print(f"Successfully signed {signed_count} binary files")

            # Create output directory if it doesn't exist
            output_dir = os.path.join(os.path.dirname(self.app_path), 'signed')
            os.makedirs(output_dir, exist_ok=True)

            # Create signed IPA
            output_filename = 'signed_' + secure_filename(os.path.basename(self.app_path))
            output_path = os.path.join(output_dir, output_filename)
            
            # Create new IPA
            current_dir = os.getcwd()
            try:
                os.chdir(ipa_extract_path)
                subprocess.run([
                    'zip', '-qr', output_path, 'Payload'
                ], check=True, capture_output=True)
            finally:
                os.chdir(current_dir)

            return True, output_path

        except Exception as e:
            return False, str(e)

        finally:
            self.cleanup()

    @staticmethod
    def generate_manifest(bundle_id, app_url, title, version='1.0'):
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

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
        """Extract and validate certificate information"""
        try:
            # Export certificate from P12
            cert_process = subprocess.run([
                'openssl', 'pkcs12',
                '-in', self.p12_path,
                '-passin', f'pass:{self.p12_password}',
                '-nokeys',
                '-nodes'
            ], capture_output=True, text=True, check=True)
            
            # Get subject information
            subject_process = subprocess.run([
                'openssl', 'x509',
                '-noout',
                '-subject'
            ], input=cert_process.stdout, capture_output=True, text=True, check=True)
            
            subject = subject_process.stdout.strip()
            
            # Verify it's an iOS signing certificate
            if 'iPhone' not in subject and 'iOS' not in subject:
                raise ValueError('Invalid certificate: Not an iOS signing certificate')
                
            return subject
        except subprocess.CalledProcessError as e:
            raise ValueError(f'Certificate validation failed: {e.stderr}')
        except Exception as e:
            raise ValueError(f'Certificate processing error: {str(e)}')

    def extract_bundle_id(self):
        """Extract bundle ID from provisioning profile"""
        try:
            with open(self.provision_path, 'rb') as f:
                content = f.read()
                # Find the XML plist data within the provisioning profile
                start = content.find(b'<?xml')
                end = content.find(b'</plist>') + 8
                if start == -1 or end == 7:  # 7 because -1 + 8 = 7
                    raise ValueError('Invalid provisioning profile format')
                    
                plist_data = plistlib.loads(content[start:end])
                app_id = plist_data.get('Entitlements', {}).get('application-identifier', '')
                if not app_id:
                    raise ValueError('No application identifier found in profile')
                    
                # Remove team ID prefix (everything before the last dot)
                return app_id.split('.')[-1]
        except Exception as e:
            raise ValueError(f'Failed to extract bundle ID: {str(e)}')

    def extract_private_key(self):
        """Extract private key from P12 certificate"""
        try:
            self.key_path = os.path.join(self.temp_dir, 'private.key')
            subprocess.run([
                'openssl', 'pkcs12',
                '-in', self.p12_path,
                '-passin', f'pass:{self.p12_password}',
                '-nocerts',
                '-nodes',  # Don't encrypt the output key
                '-out', self.key_path
            ], check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError as e:
            raise ValueError(f'Failed to extract private key: {e.stderr}')

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
            self.get_cert_info()  # Verify certificate
            self.extract_private_key()  # Extract private key

            # Copy provisioning profile
            shutil.copy2(self.provision_path, os.path.join(app_dir, 'embedded.mobileprovision'))

            # Sign the application
            for root, _, files in os.walk(app_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    if os.path.splitext(file)[1] in ['.dylib', '']:  # Sign binaries and dylibs
                        try:
                            subprocess.run([
                                'openssl', 'cms',
                                '-sign', '-binary',
                                '-in', file_path,
                                '-signer', self.p12_path,
                                '-inkey', self.key_path,
                                '-outform', 'DER',
                                '-out', os.path.join(os.path.dirname(file_path), '_CodeSignature')
                            ], check=True, capture_output=True)
                        except subprocess.CalledProcessError as e:
                            print(f"Warning: Failed to sign {file}: {e.stderr}")
                            continue

            # Create output directory if it doesn't exist
            output_dir = os.path.join(os.path.dirname(self.app_path), 'signed')
            os.makedirs(output_dir, exist_ok=True)

            # Create signed IPA
            output_filename = 'signed_' + secure_filename(os.path.basename(self.app_path))
            output_path = os.path.join(output_dir, output_filename)
            
            # Use Python's zipfile module instead of zip command
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

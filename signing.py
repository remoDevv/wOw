import os
import shutil
import tempfile
import zipfile
import plistlib
from datetime import datetime
from werkzeug.utils import secure_filename
import subprocess

class IPASigner:
    def __init__(self, ipa_path, p12_path, provision_path, p12_password):
        self.ipa_path = ipa_path
        self.p12_path = p12_path
        self.provision_path = provision_path
        self.p12_password = p12_password.encode() if isinstance(p12_password, str) else p12_password
        self.temp_dir = None
        self.cert_path = None
        self.key_path = None
        self.app_path = None
        self.signed_ipa_path = None
        
    def __enter__(self):
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()

    def cleanup(self):
        """Clean up temporary files and directories"""
        try:
            if self.cert_path and os.path.exists(self.cert_path):
                os.remove(self.cert_path)
            if self.key_path and os.path.exists(self.key_path):
                os.remove(self.key_path)
            if self.temp_dir and os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
        except Exception as e:
            print(f"Cleanup error: {str(e)}")

    def create_temp_dir(self):
        """Create temporary directory for signing process"""
        try:
            self.temp_dir = tempfile.mkdtemp()
            print(f"Created temporary directory: {self.temp_dir}")
            return True
        except Exception as e:
            raise ValueError(f"Failed to create temp directory: {str(e)}")

    def extract_ipa(self):
        """Extract IPA contents"""
        try:
            print("Extracting IPA...")
            extract_dir = os.path.join(self.temp_dir, "ipa_contents")
            with zipfile.ZipFile(self.ipa_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
            print("IPA extracted successfully")

            # Find .app directory
            payload_dir = os.path.join(extract_dir, "Payload")
            app_name = next(f for f in os.listdir(payload_dir) if f.endswith('.app'))
            self.app_path = os.path.join(payload_dir, app_name)
            print(f"Found app bundle: {self.app_path}")
            return True
        except Exception as e:
            raise ValueError(f"Failed to extract IPA: {str(e)}")

    def copy_provision(self):
        """Copy provisioning profile to app bundle"""
        try:
            embedded_path = os.path.join(self.app_path, "embedded.mobileprovision")
            shutil.copy2(self.provision_path, embedded_path)
            print("Copied provisioning profile")
            return True
        except Exception as e:
            raise ValueError(f"Failed to copy provision: {str(e)}")

    def extract_from_p12(self):
        try:
            # Create OpenSSL command with legacy providers
            env = os.environ.copy()
            env['OPENSSL_CONF'] = ''  # Prevent loading system config
            
            commands = [
                # Try with legacy provider
                ['openssl', 'pkcs12', '-in', self.p12_path, '-nodes',
                 '-out', os.path.join(self.temp_dir, 'combined.pem'),
                 '-passin', f'pass:{self.p12_password.decode()}',
                 '-legacy'],
                
                # Try without legacy provider
                ['openssl', 'pkcs12', '-in', self.p12_path, '-nodes',
                 '-out', os.path.join(self.temp_dir, 'combined.pem'),
                 '-passin', f'pass:{self.p12_password.decode()}']
            ]
            
            success = False
            last_error = None
            
            for cmd in commands:
                try:
                    subprocess.run(cmd, check=True, capture_output=True, text=True, env=env)
                    success = True
                    break
                except subprocess.CalledProcessError as e:
                    last_error = e
                    continue
            
            if not success:
                raise ValueError(f"Failed to extract certificate: {last_error.stderr if last_error else 'Unknown error'}")
                
            # Split combined PEM into certificate and key
            combined_path = os.path.join(self.temp_dir, 'combined.pem')
            self.cert_path = os.path.join(self.temp_dir, 'cert.pem')
            self.key_path = os.path.join(self.temp_dir, 'private.key')
            
            with open(combined_path, 'r') as f:
                combined = f.read()
                
            # Extract certificate and key using string manipulation
            cert_start = '-----BEGIN CERTIFICATE-----'
            cert_end = '-----END CERTIFICATE-----'
            key_start = '-----BEGIN PRIVATE KEY-----'
            key_end = '-----END PRIVATE KEY-----'
            
            cert_idx = combined.find(cert_start)
            key_idx = combined.find(key_start)
            
            if cert_idx >= 0 and key_idx >= 0:
                cert = combined[cert_idx:combined.find(cert_end) + len(cert_end)]
                key = combined[key_idx:combined.find(key_end) + len(key_end)]
                
                with open(self.cert_path, 'w') as f:
                    f.write(cert)
                with open(self.key_path, 'w') as f:
                    f.write(key)
                    
                # Clean up combined file
                os.remove(combined_path)
                return True
            else:
                raise ValueError("Failed to extract certificate and key from combined PEM")
                
        except Exception as e:
            raise ValueError(f"Failed to extract certificate and key: {str(e)}")

    def sign_file(self, filepath):
        """Sign a single file with OpenSSL"""
        try:
            # Use OpenSSL CMS for signing
            env = os.environ.copy()
            env['OPENSSL_CONF'] = ''  # Prevent loading system config
            
            cmd = [
                'openssl', 'cms', '-sign', '-binary', '-noattr',
                '-signer', self.cert_path,
                '-inkey', self.key_path,
                '-outform', 'DER',
                '-in', filepath,
                '-out', filepath + '.sig'
            ]
            
            subprocess.run(cmd, check=True, capture_output=True, text=True, env=env)
            return True
        except Exception as e:
            print(f"Failed to sign file {filepath}: {str(e)}")
            return False

    def sign_application(self):
        """Sign the application using OpenSSL"""
        try:
            # Sign all executable files
            for root, dirs, files in os.walk(self.app_path):
                for file in files:
                    if file.endswith(('.dylib', '') or 'Frameworks' in root):
                        filepath = os.path.join(root, file)
                        if os.path.isfile(filepath):
                            self.sign_file(filepath)
            return True
        except Exception as e:
            raise ValueError(f"Failed to sign application: {str(e)}")

    def package_ipa(self):
        """Create signed IPA file"""
        try:
            ipa_name = os.path.splitext(os.path.basename(self.ipa_path))[0]
            signed_name = f"{ipa_name}_signed_{datetime.now().strftime('%Y%m%d_%H%M%S')}.ipa"
            self.signed_ipa_path = os.path.join(os.path.dirname(self.ipa_path), signed_name)
            
            with zipfile.ZipFile(self.signed_ipa_path, 'w', zipfile.ZIP_STORED) as zf:
                for root, dirs, files in os.walk(os.path.dirname(self.app_path)):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arc_path = os.path.relpath(file_path, os.path.dirname(self.app_path))
                        zf.write(file_path, arc_path)
            
            return self.signed_ipa_path
        except Exception as e:
            raise ValueError(f"Failed to package IPA: {str(e)}")

    def extract_bundle_id(self):
        """Extract bundle ID from Info.plist"""
        try:
            info_plist = os.path.join(self.app_path, 'Info.plist')
            with open(info_plist, 'rb') as f:
                plist = plistlib.load(f)
            return plist.get('CFBundleIdentifier')
        except Exception as e:
            raise ValueError(f"Failed to extract bundle ID: {str(e)}")

    def sign_ipa(self):
        """Main signing process"""
        try:
            self.create_temp_dir()
            self.extract_ipa()
            self.copy_provision()
            self.extract_from_p12()
            self.sign_application()
            signed_path = self.package_ipa()
            return True, signed_path
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

import os
import shutil
import tempfile
import zipfile
import plistlib
from datetime import datetime
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
            if not self.temp_dir:
                self.create_temp_dir()
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
            if not self.app_path:
                raise ValueError("App path not set")
            embedded_path = os.path.join(self.app_path, "embedded.mobileprovision")
            shutil.copy2(self.provision_path, embedded_path)
            print("Copied provisioning profile")
            return True
        except Exception as e:
            raise ValueError(f"Failed to copy provision: {str(e)}")

    def extract_certificates(self):
        """Extract certificates with improved Linux compatibility"""
        try:
            if not self.temp_dir:
                self.create_temp_dir()
            self.cert_path = os.path.join(self.temp_dir, 'cert.pem')
            self.key_path = os.path.join(self.temp_dir, 'key.pem')
            
            # Create OpenSSL config file to force legacy provider
            ssl_config = os.path.join(self.temp_dir, 'openssl.cnf')
            with open(ssl_config, 'w') as f:
                f.write('''
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
legacy = legacy_sect

[default_sect]
activate = 1

[legacy_sect]
activate = 1
''')
            
            # Set OpenSSL config environment
            env = os.environ.copy()
            env['OPENSSL_CONF'] = ssl_config
            
            # Extract certificate
            cert_cmd = [
                'openssl', 'pkcs12', '-in', self.p12_path,
                '-clcerts', '-nokeys', '-out', self.cert_path,
                '-passin', f'pass:{self.p12_password.decode()}'
            ]
            
            # Extract private key
            key_cmd = [
                'openssl', 'pkcs12', '-in', self.p12_path,
                '-nocerts', '-nodes', '-out', self.key_path,
                '-passin', f'pass:{self.p12_password.decode()}'
            ]
            
            for cmd in [cert_cmd, key_cmd]:
                result = subprocess.run(cmd, capture_output=True, text=True, env=env)
                if result.returncode != 0:
                    raise ValueError(f"Certificate extraction failed: {result.stderr}")
            
            # Verify certificate and key
            cert_verify = subprocess.run(
                ['openssl', 'x509', '-in', self.cert_path, '-noout'],
                capture_output=True, text=True, env=env
            )
            
            key_verify = subprocess.run(
                ['openssl', 'rsa', '-in', self.key_path, '-check', '-noout'],
                capture_output=True, text=True, env=env
            )
            
            if cert_verify.returncode != 0 or key_verify.returncode != 0:
                raise ValueError("Invalid certificate or private key")
                
            return True
            
        except Exception as e:
            raise ValueError(f"Failed to extract certificates: {str(e)}")

    def sign_file(self, file_path):
        """Sign a file using OpenSSL CMS"""
        try:
            if not self.temp_dir or not self.cert_path or not self.key_path:
                raise ValueError("Certificate paths not set")

            # Create temporary files
            content_path = os.path.join(self.temp_dir, 'content.bin')
            sig_path = os.path.join(self.temp_dir, 'signature.sig')
            
            # Copy file to temp location
            shutil.copy2(file_path, content_path)
            
            # Simplified CMS signing command
            sign_cmd = [
                'openssl', 'cms', '-sign',
                '-signer', self.cert_path,
                '-inkey', self.key_path,
                '-binary',  # Remove -noattr flag
                '-outform', 'DER',
                '-in', content_path,
                '-out', sig_path
            ]
            
            env = os.environ.copy()
            env['OPENSSL_CONF'] = os.path.join(self.temp_dir, 'openssl.cnf')
            
            # Execute signing
            result = subprocess.run(sign_cmd, capture_output=True, text=True, env=env)
            if result.returncode != 0:
                raise ValueError(f"Failed to sign file: {result.stderr}")
            
            # Replace original with signed version
            shutil.move(sig_path, file_path)
            
            # Clean up
            if os.path.exists(content_path):
                os.remove(content_path)
            
            return True
            
        except Exception as e:
            print(f"Failed to sign {file_path}: {str(e)}")
            return False

    def sign_ipa(self):
        """Main signing process with improved error handling and logging"""
        try:
            print("Starting IPA signing process...")
            self.create_temp_dir()
            print("Extracting IPA contents...")
            self.extract_ipa()
            print("Copying provisioning profile...")
            self.copy_provision()
            print("Extracting certificates...")
            self.extract_certificates()
            
            print("Signing application files...")
            # Sign all required files
            for root, dirs, files in os.walk(self.app_path):
                for file in files:
                    if file.endswith(('.dylib', '')):
                        file_path = os.path.join(root, file)
                        if os.path.isfile(file_path):
                            print(f"Signing {file}")
                            if not self.sign_file(file_path):
                                raise ValueError(f"Failed to sign {file}")
            
            print("Packaging signed IPA...")
            signed_path = self.package_ipa()
            print("Signing completed successfully")
            return True, signed_path
            
        except Exception as e:
            error_msg = f"Signing failed: {str(e)}"
            print(error_msg)
            return False, error_msg
            
        finally:
            self.cleanup()

    def package_ipa(self):
        """Create signed IPA file"""
        try:
            if not self.app_path:
                raise ValueError("App path not set")
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
            if not self.app_path:
                raise ValueError("App path not set")
            info_plist = os.path.join(self.app_path, 'Info.plist')
            with open(info_plist, 'rb') as f:
                plist = plistlib.load(f)
            return plist.get('CFBundleIdentifier')
        except Exception as e:
            raise ValueError(f"Failed to extract bundle ID: {str(e)}")

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

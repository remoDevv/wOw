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

    def extract_certificates(self):
        """Extract certificates with improved Linux compatibility"""
        try:
            self.cert_path = os.path.join(self.temp_dir, 'cert.pem')
            self.key_path = os.path.join(self.temp_dir, 'key.pem')
            
            # First attempt: Extract everything to a single file
            combined_path = os.path.join(self.temp_dir, 'combined.pem')
            
            # Basic command without any special providers
            basic_cmd = [
                'openssl', 'pkcs12', '-in', self.p12_path,
                '-nodes', '-out', combined_path,
                '-passin', f'pass:{self.p12_password.decode()}'
            ]
            
            result = subprocess.run(basic_cmd, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"Basic extraction failed: {result.stderr}")
                # Fallback: try with -legacy flag
                legacy_cmd = basic_cmd + ['-legacy']
                result = subprocess.run(legacy_cmd, capture_output=True, text=True)
                if result.returncode != 0:
                    raise ValueError(f"Certificate extraction failed: {result.stderr}")
            
            # Read the combined file
            with open(combined_path, 'r') as f:
                content = f.read()
            
            # Split the content into certificate and private key
            cert_content = ""
            key_content = ""
            current_section = None
            
            for line in content.split('\n'):
                if '-----BEGIN CERTIFICATE-----' in line:
                    current_section = 'cert'
                    cert_content = line + '\n'
                elif '-----BEGIN PRIVATE KEY-----' in line:
                    current_section = 'key'
                    key_content = line + '\n'
                elif '-----END CERTIFICATE-----' in line:
                    cert_content += line + '\n'
                    current_section = None
                elif '-----END PRIVATE KEY-----' in line:
                    key_content += line + '\n'
                    current_section = None
                elif current_section == 'cert':
                    cert_content += line + '\n'
                elif current_section == 'key':
                    key_content += line + '\n'
            
            # Write separated files
            if cert_content and key_content:
                with open(self.cert_path, 'w') as f:
                    f.write(cert_content.strip())
                with open(self.key_path, 'w') as f:
                    f.write(key_content.strip())
            else:
                raise ValueError("Failed to extract certificate or private key from combined file")
            
            # Verify the extracted files
            verify_cert = subprocess.run(['openssl', 'x509', '-in', self.cert_path, '-noout'], 
                                       capture_output=True, text=True)
            verify_key = subprocess.run(['openssl', 'rsa', '-in', self.key_path, '-check', '-noout'],
                                      capture_output=True, text=True)
            
            if verify_cert.returncode != 0 or verify_key.returncode != 0:
                raise ValueError("Invalid certificate or private key")
            
            # Clean up combined file
            os.remove(combined_path)
            return True
            
        except Exception as e:
            if 'combined_path' in locals() and os.path.exists(combined_path):
                os.remove(combined_path)
            raise ValueError(f"Failed to extract certificates: {str(e)}")

    def sign_file(self, file_path):
        """Sign a file using OpenSSL CMS"""
        try:
            # Generate temporary files
            content_path = os.path.join(self.temp_dir, 'content.bin')
            sig_path = os.path.join(self.temp_dir, 'signature.p7s')
            
            # Copy file to temp location
            shutil.copy2(file_path, content_path)
            
            # Sign with CMS
            sign_cmd = [
                'openssl', 'cms', '-sign', '-binary',
                '-signer', self.cert_path,
                '-inkey', self.key_path,
                '-in', content_path,
                '-out', sig_path,
                '-outform', 'DER'
            ]
            
            result = subprocess.run(sign_cmd, capture_output=True, text=True)
            if result.returncode != 0:
                raise ValueError(f"Signing failed: {result.stderr}")
                
            # Verify signature
            verify_cmd = [
                'openssl', 'cms', '-verify',
                '-binary', '-inform', 'DER',
                '-in', sig_path,
                '-content', content_path,
                '-certfile', self.cert_path
            ]
            
            result = subprocess.run(verify_cmd, capture_output=True, text=True)
            if result.returncode != 0:
                raise ValueError(f"Signature verification failed: {result.stderr}")
                
            # Replace original with signed version
            shutil.move(sig_path, file_path + '.sig')
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

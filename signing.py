import os
import shutil
import tempfile
import subprocess
import plistlib
import zipfile
from datetime import datetime
from werkzeug.utils import secure_filename

class IPASigner:
    def __init__(self, ipa_path, p12_path, provision_path, p12_password):
        self.ipa_path = ipa_path
        self.p12_path = p12_path
        self.provision_path = provision_path
        self.p12_password = p12_password
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

    def extract_certificate(self):
        """Extract certificate from P12"""
        try:
            if not self.temp_dir:
                self.temp_dir = tempfile.mkdtemp()
            self.cert_path = os.path.join(self.temp_dir, 'cert.pem')
            
            # Write password to temp file
            pwd_path = os.path.join(self.temp_dir, 'pwd.txt')
            with open(pwd_path, 'w') as f:
                f.write(self.p12_password)
            
            try:
                # Try multiple OpenSSL configurations
                commands = [
                    ['openssl', 'pkcs12', '-in', self.p12_path, '-clcerts', '-nokeys',
                     '-out', self.cert_path, '-passin', f'file:{pwd_path}',
                     '-legacy'],
                    ['openssl', 'pkcs12', '-in', self.p12_path, '-clcerts', '-nokeys',
                     '-out', self.cert_path, '-passin', f'file:{pwd_path}',
                     '-provider', 'legacy', '-provider', 'default'],
                    ['openssl', 'pkcs12', '-in', self.p12_path, '-clcerts', '-nokeys',
                     '-out', self.cert_path, '-passin', f'file:{pwd_path}']
                ]
                
                success = False
                last_error = None
                
                for cmd in commands:
                    try:
                        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
                        success = True
                        break
                    except subprocess.CalledProcessError as e:
                        last_error = e
                        continue
                
                if not success and last_error:
                    raise last_error
                    
                return True
                
            finally:
                if os.path.exists(pwd_path):
                    os.remove(pwd_path)
                    
        except subprocess.CalledProcessError as e:
            raise ValueError(f"Failed to extract certificate: {e.stderr}")
        except Exception as e:
            raise ValueError(f"Certificate extraction error: {str(e)}")

    def extract_private_key(self):
        """Extract private key from P12"""
        try:
            if not self.temp_dir:
                self.temp_dir = tempfile.mkdtemp()
            self.key_path = os.path.join(self.temp_dir, 'private.key')
            
            pwd_path = os.path.join(self.temp_dir, 'pwd.txt')
            with open(pwd_path, 'w') as f:
                f.write(self.p12_password)
            
            try:
                commands = [
                    ['openssl', 'pkcs12', '-in', self.p12_path, '-nocerts', '-nodes',
                     '-out', self.key_path, '-passin', f'file:{pwd_path}',
                     '-legacy'],
                    ['openssl', 'pkcs12', '-in', self.p12_path, '-nocerts', '-nodes',
                     '-out', self.key_path, '-passin', f'file:{pwd_path}',
                     '-provider', 'legacy', '-provider', 'default'],
                    ['openssl', 'pkcs12', '-in', self.p12_path, '-nocerts', '-nodes',
                     '-out', self.key_path, '-passin', f'file:{pwd_path}']
                ]
                
                success = False
                last_error = None
                
                for cmd in commands:
                    try:
                        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
                        success = True
                        break
                    except subprocess.CalledProcessError as e:
                        last_error = e
                        continue
                
                if not success and last_error:
                    raise last_error
                    
                return True
                
            finally:
                if os.path.exists(pwd_path):
                    os.remove(pwd_path)
                    
        except subprocess.CalledProcessError as e:
            raise ValueError(f"Failed to extract private key: {e.stderr}")
        except Exception as e:
            raise ValueError(f"Private key extraction error: {str(e)}")

    def sign_application(self):
        """Sign the application using extracted certificate and key"""
        try:
            entitlements_path = os.path.join(self.temp_dir, 'entitlements.plist')
            
            # Extract entitlements from provisioning profile
            subprocess.run([
                'security', 'cms', '-D', '-i', self.provision_path,
                '-o', entitlements_path
            ], check=True)

            # Sign all dylib files first
            for root, dirs, files in os.walk(self.app_path):
                for file in files:
                    if file.endswith('.dylib'):
                        dylib_path = os.path.join(root, file)
                        subprocess.run([
                            'codesign', '-f', '-s', self.cert_path,
                            '--preserve-metadata=identifier,entitlements,requirements',
                            '--generate-entitlement-der',
                            '--timestamp=none',
                            dylib_path
                        ], check=True)

            # Sign the main application
            subprocess.run([
                'codesign', '-f', '-s', self.cert_path,
                '--entitlements', entitlements_path,
                '--generate-entitlement-der',
                '--timestamp=none',
                self.app_path
            ], check=True)

            return True
        except subprocess.CalledProcessError as e:
            raise ValueError(f"Failed to sign application: {e.stderr}")
        except Exception as e:
            raise ValueError(f"Application signing error: {str(e)}")

    def package_ipa(self):
        """Create signed IPA file"""
        try:
            ipa_name = os.path.splitext(os.path.basename(self.ipa_path))[0]
            signed_name = f"{ipa_name}_signed_{datetime.now().strftime('%Y%m%d_%H%M%S')}.ipa"
            self.signed_ipa_path = os.path.join(os.path.dirname(self.ipa_path), signed_name)
            
            # Create IPA from Payload directory
            payload_dir = os.path.dirname(os.path.dirname(self.app_path))
            shutil.make_archive(self.signed_ipa_path, 'zip', payload_dir)
            os.rename(f"{self.signed_ipa_path}.zip", self.signed_ipa_path)
            
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
            self.extract_certificate()
            self.extract_private_key()
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

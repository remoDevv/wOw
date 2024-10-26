import os
import shutil
import tempfile
import subprocess
import plistlib
import zipfile
from datetime import datetime
from werkzeug.utils import secure_filename
from OpenSSL import crypto

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

    def extract_from_p12(self):
        """Extract certificate and private key from P12 using OpenSSL"""
        try:
            # Read P12 file
            with open(self.p12_path, 'rb') as f:
                p12 = crypto.load_pkcs12(f.read(), self.p12_password)
            
            # Extract certificate
            cert = p12.get_certificate()
            self.cert_path = os.path.join(self.temp_dir, 'cert.pem')
            with open(self.cert_path, 'wb') as f:
                f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
            
            # Extract private key
            pkey = p12.get_privatekey()
            self.key_path = os.path.join(self.temp_dir, 'private.key')
            with open(self.key_path, 'wb') as f:
                f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey))
                
            return True
        except Exception as e:
            raise ValueError(f"Failed to extract certificate and key: {str(e)}")

    def sign_application(self):
        """Sign the application using extracted certificate and key"""
        try:
            # Extract entitlements
            entitlements_path = os.path.join(self.temp_dir, 'entitlements.plist')
            subprocess.run([
                'security', 'cms', '-D', '-i', self.provision_path,
                '-o', entitlements_path
            ], check=True)

            # Generate code directory hash
            codesign_alloc = subprocess.run([
                'codesign_allocate', '-i', os.path.join(self.app_path, '_CodeSignature/CodeResources'),
                '-a', 'arm64'
            ], capture_output=True, check=True)

            # Sign all components
            for root, dirs, files in os.walk(self.app_path):
                for file in files:
                    if file.endswith(('.dylib', '.framework/Versions/A', '')):
                        filepath = os.path.join(root, file)
                        
                        # Generate CMS signature
                        cms = crypto.CMS()
                        with open(self.key_path, 'rb') as f:
                            key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())
                        with open(self.cert_path, 'rb') as f:
                            cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
                        
                        # Sign with CMS
                        cms.sign(cert, key, [cert], flags=crypto.CMS_BINARY)
                        
                        # Apply signature
                        subprocess.run([
                            'codesign', '-f', '-s', '-',
                            '--generate-entitlement-der',
                            '--preserve-metadata=identifier,entitlements,requirements',
                            '--timestamp=none',
                            filepath
                        ], input=cms.to_der(), check=True)

            return True
        except Exception as e:
            raise ValueError(f"Failed to sign application: {str(e)}")

    def package_ipa(self):
        """Create signed IPA file"""
        try:
            ipa_name = os.path.splitext(os.path.basename(self.ipa_path))[0]
            signed_name = f"{ipa_name}_signed_{datetime.now().strftime('%Y%m%d_%H%M%S')}.ipa"
            self.signed_ipa_path = os.path.join(os.path.dirname(self.ipa_path), signed_name)
            
            # Create IPA maintaining signatures
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
            self.extract_from_p12()  # Updated to use new OpenSSL method
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

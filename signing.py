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
        self.cert_path = None

    def cleanup(self):
        """Clean up temporary files and directories"""
        try:
            if self.key_path and os.path.exists(self.key_path):
                os.remove(self.key_path)
            if self.cert_path and os.path.exists(self.cert_path):
                os.remove(self.cert_path)
            if self.temp_dir and os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
        except Exception as e:
            print(f"Warning: Cleanup failed: {str(e)}")

    def extract_certificate(self):
        """Extract certificate from P12 file with enhanced compatibility"""
        try:
            if self.temp_dir is None:
                self.temp_dir = tempfile.mkdtemp()
            self.cert_path = os.path.join(self.temp_dir, 'cert.pem')
            
            # Try different OpenSSL commands with various options
            commands = [
                # Try with legacy and no password first
                ['openssl', 'pkcs12', '-in', self.p12_path, '-clcerts', '-nokeys',
                 '-out', self.cert_path, '-nodes', '-legacy'],
                
                # Try with password and legacy
                ['openssl', 'pkcs12', '-in', self.p12_path, '-clcerts', '-nokeys',
                 '-out', self.cert_path, '-passin', f'pass:{self.p12_password}', '-legacy'],
                 
                # Try with default algorithms
                ['openssl', 'pkcs12', '-in', self.p12_path, '-clcerts', '-nokeys',
                 '-out', self.cert_path, '-passin', f'pass:{self.p12_password}'],
                 
                # Try with nodes option
                ['openssl', 'pkcs12', '-in', self.p12_path, '-clcerts', '-nokeys',
                 '-out', self.cert_path, '-nodes', '-passin', f'pass:{self.p12_password}']
            ]
            
            last_error = None
            for cmd in commands:
                try:
                    subprocess.run(cmd, check=True, capture_output=True, text=True)
                    return True
                except subprocess.CalledProcessError as e:
                    last_error = e
                    continue
                    
            if last_error:
                raise ValueError(f'All certificate extraction attempts failed: {last_error.stderr}')
                
            return True
        except Exception as e:
            raise ValueError(f'Failed to extract certificate: {str(e)}')

    def extract_private_key(self):
        """Extract private key from P12 certificate with enhanced compatibility"""
        try:
            if self.temp_dir is None:
                self.temp_dir = tempfile.mkdtemp()
            self.key_path = os.path.join(self.temp_dir, 'private.key')
            
            commands = [
                # Try with legacy and no password
                ['openssl', 'pkcs12', '-in', self.p12_path, '-nocerts',
                 '-out', self.key_path, '-nodes', '-legacy'],
                
                # Try with password and legacy
                ['openssl', 'pkcs12', '-in', self.p12_path, '-nocerts',
                 '-out', self.key_path, '-passin', f'pass:{self.p12_password}', '-legacy'],
                 
                # Try with default algorithms
                ['openssl', 'pkcs12', '-in', self.p12_path, '-nocerts',
                 '-out', self.key_path, '-passin', f'pass:{self.p12_password}'],
                 
                # Try with nodes option
                ['openssl', 'pkcs12', '-in', self.p12_path, '-nocerts',
                 '-out', self.key_path, '-nodes', '-passin', f'pass:{self.p12_password}']
            ]
            
            last_error = None
            for cmd in commands:
                try:
                    subprocess.run(cmd, check=True, capture_output=True, text=True)
                    return True
                except subprocess.CalledProcessError as e:
                    last_error = e
                    continue
                    
            if last_error:
                raise ValueError(f'All private key extraction attempts failed: {last_error.stderr}')
                
            return True
        except Exception as e:
            raise ValueError(f'Failed to extract private key: {str(e)}')

    def verify_file_exists(self, file_path, description):
        """Verify file existence and type"""
        if not os.path.exists(file_path):
            raise ValueError(f'{description} not found: {file_path}')
        if not os.path.isfile(file_path):
            raise ValueError(f'{description} is not a file: {file_path}')

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

    @staticmethod
    def is_binary_file(file_path):
        """Check if a file is binary"""
        # Skip known non-binary files
        skip_extensions = {
            '.strings', '.plist', '.nib', '.mom', 
            '.ttf', '.png', '.jpg', '.jpeg', '.gif',
            '.css', '.js', '.html', '.json', '.xml',
            '.txt', '.md', '.csv', '.mobileprovision'
        }
        if any(file_path.lower().endswith(ext) for ext in skip_extensions):
            return False
            
        try:
            # Check if file is Mach-O binary
            result = subprocess.run(
                ['file', file_path],
                capture_output=True,
                text=True,
                check=True
            )
            return 'Mach-O' in result.stdout
        except:
            # Fallback to basic binary check
            try:
                with open(file_path, 'rb') as f:
                    chunk = f.read(1024)
                    return b'\x00' in chunk
            except:
                return False

    def sign_binary(self, file_path):
        """Sign a binary file using OpenSSL with improved error handling"""
        try:
            # Skip non-binary files
            if not self.is_binary_file(file_path):
                return False
                
            binary_name = os.path.basename(file_path)
            print(f"Signing binary: {binary_name}")
            
            # Verify all required files exist
            self.verify_file_exists(self.cert_path, "Certificate")
            self.verify_file_exists(self.key_path, "Private key")
            self.verify_file_exists(file_path, "Binary file")
            
            sig_path = file_path + '.sig'
            cmd = [
                'openssl', 'cms',
                '-sign', '-binary',
                '-in', file_path,
                '-signer', self.cert_path,
                '-inkey', self.key_path,
                '-certfile', self.provision_path,
                '-outform', 'DER',
                '-out', sig_path
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
            
            print(f"Successfully signed {binary_name}")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"Failed to sign {os.path.basename(file_path)}: {e.stderr}")
            return False
        except Exception as e:
            print(f"Error signing {os.path.basename(file_path)}: {str(e)}")
            return False

    def sign_ipa(self):
        try:
            print("Starting IPA signing process...")
            
            # Validate input files
            if not os.path.exists(self.app_path):
                raise ValueError(f"IPA file not found: {self.app_path}")
            if not os.path.exists(self.p12_path):
                raise ValueError(f"P12 certificate not found: {self.p12_path}")
            if not os.path.exists(self.provision_path):
                raise ValueError(f"Provisioning profile not found: {self.provision_path}")
                
            # Create temp directory
            self.temp_dir = tempfile.mkdtemp()
            print(f"Created temporary directory: {self.temp_dir}")
            
            # Extract IPA
            ipa_extract_path = os.path.join(self.temp_dir, 'ipa_contents')
            os.makedirs(ipa_extract_path)
            print("Extracting IPA...")
            
            try:
                subprocess.run(['unzip', '-q', self.app_path, '-d', ipa_extract_path], check=True)
                print("IPA extracted successfully")
            except subprocess.CalledProcessError as e:
                raise ValueError(f"Failed to extract IPA: {e}")
                
            # Find main app bundle
            app_dir = None
            for root, dirs, _ in os.walk(os.path.join(ipa_extract_path, 'Payload')):
                for dir in dirs:
                    if dir.endswith('.app'):
                        app_dir = os.path.join(root, dir)
                        break
                if app_dir:
                    break
                    
            if not app_dir:
                raise ValueError("No .app bundle found in IPA")
                
            print(f"Found app bundle: {app_dir}")
            
            # Copy provisioning profile
            prov_dest = os.path.join(app_dir, 'embedded.mobileprovision')
            shutil.copy2(self.provision_path, prov_dest)
            print("Copied provisioning profile")
            
            # Extract certificate and private key
            print("Extracting certificate and private key...")
            self.extract_certificate()
            self.extract_private_key()
            print("Certificate and private key extracted successfully")
            
            # Find main executable
            executable = None
            info_plist_path = os.path.join(app_dir, 'Info.plist')
            if os.path.exists(info_plist_path):
                try:
                    with open(info_plist_path, 'rb') as f:
                        info_plist = plistlib.load(f)
                        executable = info_plist.get('CFBundleExecutable')
                        if executable:
                            executable = os.path.join(app_dir, executable)
                except:
                    pass
                    
            if not executable or not os.path.exists(executable):
                print("Warning: Could not find main executable from Info.plist")
                # Try to find the main executable manually
                for file in os.listdir(app_dir):
                    if not file.endswith(('.plist', '.mobileprovision', '.png', '.jpg')):
                        possible_exec = os.path.join(app_dir, file)
                        if os.path.isfile(possible_exec) and os.access(possible_exec, os.X_OK):
                            executable = possible_exec
                            break
                            
            if not executable:
                raise ValueError("Could not find main executable")
                
            print(f"Found main executable: {executable}")
            
            # Sign the main executable
            if not self.sign_binary(executable):
                raise ValueError("Failed to sign main executable")
            
            # Create signed output
            output_dir = os.path.dirname(self.app_path)
            output_filename = 'signed_' + os.path.basename(self.app_path)
            output_path = os.path.join(output_dir, output_filename)
            
            print("Creating signed IPA...")
            current_dir = os.getcwd()
            try:
                os.chdir(ipa_extract_path)
                subprocess.run(['zip', '-qr', output_path, 'Payload'], check=True)
                print(f"Created signed IPA: {output_path}")
            finally:
                os.chdir(current_dir)
                
            return True, output_path
            
        except Exception as e:
            print(f"Error during signing: {str(e)}")
            return False, str(e)
            
        finally:
            if self.temp_dir and os.path.exists(self.temp_dir):
                try:
                    shutil.rmtree(self.temp_dir)
                    print("Cleaned up temporary directory")
                except:
                    print("Warning: Failed to clean up temporary directory")

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
        
        # Add icons if provided
        if icon_url:
            manifest['items'][0]['assets'].append({
                'kind': 'display-image',
                'url': icon_url,
                'needs-shine': True
            })
        if full_size_icon_url:
            manifest['items'][0]['assets'].append({
                'kind': 'full-size-image',
                'url': full_size_icon_url,
                'needs-shine': True
            })
        
        return plistlib.dumps(manifest)

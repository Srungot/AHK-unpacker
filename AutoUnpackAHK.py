import sys
import os
import pefile
import colorama
import subprocess
import tempfile
import shutil
import platform
import requests
import zipfile
import io
from colorama import Fore, Style

colorama.init()

def download_upx():
    temp_dir = tempfile.mkdtemp()
    system = platform.system().lower()
    arch = platform.architecture()[0]
    
    print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Downloading UPX...")
    
    try:
        if system == "windows":
            if arch == "64bit":
                url = "https://github.com/upx/upx/releases/download/v4.2.2/upx-4.2.2-win64.zip"
            else:
                url = "https://github.com/upx/upx/releases/download/v4.2.2/upx-4.2.2-win32.zip"
        elif system == "linux":
            if arch == "64bit":
                url = "https://github.com/upx/upx/releases/download/v4.2.2/upx-4.2.2-amd64_linux.tar.xz"
            else:
                url = "https://github.com/upx/upx/releases/download/v4.2.2/upx-4.2.2-i386_linux.tar.xz"
        elif system == "darwin":   
            url = "https://github.com/upx/upx/releases/download/v4.2.2/upx-4.2.2-amd64_macos.tar.xz"
        else:
            print(f"{Fore.RED}[!]{Style.RESET_ALL} Unsupported operating system: {system}")
            return None
        
        response = requests.get(url)
        if response.status_code != 200:
            print(f"{Fore.RED}[!]{Style.RESET_ALL} Failed to download UPX: HTTP {response.status_code}")
            return None
        
        if url.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(response.content)) as zip_ref:
                zip_ref.extractall(temp_dir)
        else:   
            import tarfile
            with tarfile.open(fileobj=io.BytesIO(response.content), mode="r:xz") as tar_ref:
                tar_ref.extractall(temp_dir)
        
        upx_exe = None
        for root, _, files in os.walk(temp_dir):
            for file in files:
                if file.lower() == "upx.exe" or file.lower() == "upx":
                    upx_exe = os.path.join(root, file)
                    break
            if upx_exe:
                break
        
        if not upx_exe:
            print(f"{Fore.RED}[!]{Style.RESET_ALL} UPX executable not found in the downloaded package")
            shutil.rmtree(temp_dir, ignore_errors=True)
            return None
        
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} UPX downloaded successfully")
        return upx_exe, temp_dir
    except Exception as e:
        print(f"{Fore.RED}[!]{Style.RESET_ALL} Error downloading UPX: {str(e)}")
        shutil.rmtree(temp_dir, ignore_errors=True)
        return None

def is_upx_packed(pe):
    for section in pe.sections:
        name = section.Name.decode().rstrip('\x00')
        if name == "UPX0" or name == "UPX1":
            return True
    return False

def check_upx_availability():
    try:
        subprocess.run(["upx", "-V"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        return "upx", None         
    except FileNotFoundError:
        return None

def unpack_upx(exe_path, upx_command=None, upx_dir=None):
    temp_dir = tempfile.mkdtemp()
    temp_file = os.path.join(temp_dir, os.path.basename(exe_path))
    
    try:
        shutil.copy2(exe_path, temp_file)
        print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Attempting to unpack UPX compressed file...")
        
        if upx_command == "upx":
            cmd = ["upx", "-d", temp_file]
        else:
            cmd = [upx_command, "-d", temp_file]
        
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False
        )
        
        if result.returncode != 0:
            print(f"{Fore.RED}[!]{Style.RESET_ALL} UPX decompression failed: {result.stderr}")
            shutil.rmtree(temp_dir, ignore_errors=True)
            if upx_dir:           
                shutil.rmtree(upx_dir, ignore_errors=True)
            return None
        
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Successfully unpacked UPX compressed file")
        return temp_file, temp_dir, upx_dir
    except Exception as e:
        print(f"{Fore.RED}[!]{Style.RESET_ALL} Error during UPX unpacking: {str(e)}")
        shutil.rmtree(temp_dir, ignore_errors=True)
        if upx_dir:           
            shutil.rmtree(upx_dir, ignore_errors=True)
        return None

def extract_compiler_version(script_data):
    lines = script_data.split(b'\n')
    if lines and lines[0].startswith(b'; <COMPILER:'):
        version_line = lines[0].decode('utf-8', errors='ignore')
        version = version_line.split(':', 1)[1].strip().rstrip('>')
        return version
    return None

def extract_ahk_script(exe_path):
    try:
        pe = pefile.PE(exe_path)
        
        print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Analyzing file: {Fore.RED}{exe_path}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Found {len(pe.sections)} sections in the PE file")
        
        upx_packed = is_upx_packed(pe)
        if upx_packed:
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} File appears to be UPX compressed")
            
            upx_system = check_upx_availability()
            
            if upx_system:
                upx_command, upx_dir = upx_system
            else:
                print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} UPX not found in system, downloading...")
                download_result = download_upx()
                if download_result:
                    upx_command, upx_dir = download_result
                else:
                    print(f"{Fore.RED}[!]{Style.RESET_ALL} Failed to download UPX. Cannot unpack compressed file.")
                    upx_command, upx_dir = None, None
            
            if upx_command:
                unpacked_result = unpack_upx(exe_path, upx_command, upx_dir)
                if unpacked_result:
                    unpacked_file, temp_dir, upx_dir = unpacked_result
                    
                    try:
                        result = extract_ahk_script(unpacked_file)
                        shutil.rmtree(temp_dir, ignore_errors=True)
                        if upx_dir:
                            shutil.rmtree(upx_dir, ignore_errors=True)
                        return result
                    except Exception as e:
                        print(f"{Fore.RED}[!]{Style.RESET_ALL} Error processing unpacked file: {str(e)}")
                        shutil.rmtree(temp_dir, ignore_errors=True)
                        if upx_dir:
                            shutil.rmtree(upx_dir, ignore_errors=True)
        
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Resource directory found")
            resource_count = 0
            rcdata_count = 0
            
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                resource_count += 1
                resource_name = "Unknown"
                
                if resource_type.id in pefile.RESOURCE_TYPE:
                    resource_name = [k for k, v in pefile.RESOURCE_TYPE.items() if v == resource_type.id][0]
                
                print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Resource type: {resource_name} (ID: {resource_type.id})")
                
                if resource_type.id == pefile.RESOURCE_TYPE['RT_RCDATA']:
                    for resource_id in resource_type.directory.entries:
                        rcdata_count += 1
                        
                        if hasattr(resource_id, 'name'):
                            try:
                                name_str = str(resource_id.name)
                                print(f"{Fore.CYAN}[+]{Style.RESET_ALL} RCDATA resource found (Name: {Fore.RED}{name_str}{Style.RESET_ALL})")
                                
                                if "AUTOHOTKEY" in name_str.upper():
                                    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Found resource with name containing 'AUTOHOTKEY'")
                                    
                                    for resource_lang in resource_id.directory.entries:
                                        data_rva = resource_lang.data.struct.OffsetToData
                                        size = resource_lang.data.struct.Size
                                        print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Language: {resource_lang.id}, Size: {size} bytes")
                                        
                                        data = pe.get_memory_mapped_image()[data_rva:data_rva + size]
                                        
                                        preview = data[:100].replace(b'\r', b'\\r').replace(b'\n', b'\\n')
                                        
                                        return data
                            except Exception as e:
                                print(f"{Fore.RED}[!]{Style.RESET_ALL} Error processing resource name: {str(e)}")
                        else:
                            print(f"{Fore.CYAN}[+]{Style.RESET_ALL} RCDATA resource found (ID: {resource_id.id})")
                        
                        for resource_lang in resource_id.directory.entries:
                            data_rva = resource_lang.data.struct.OffsetToData
                            size = resource_lang.data.struct.Size
                            print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Language: {resource_lang.id}, Size: {size} bytes")
                            
                            data = pe.get_memory_mapped_image()[data_rva:data_rva + size]
                            
                            preview = data[:100].replace(b'\r', b'\\r').replace(b'\n', b'\\n')
                            print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Preview: {preview}")
                            
                            if b"AutoHotkey Script" in data:
                                print(f"{Fore.GREEN}[+]{Style.RESET_ALL} AutoHotkey Script found in content!")
                                return data
            
            print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Total resources: {resource_count}, RCDATA resources: {rcdata_count}")
        else:
            print(f"{Fore.YELLOW}[-]{Style.RESET_ALL} No resource directory found in the executable")
        
        return None
    except Exception as e:
        print(f"{Fore.RED}[!]{Style.RESET_ALL} Error processing file: {str(e)}")
        return None

def main():
    if len(sys.argv) != 2:
        print(f"{Fore.RED}[!]{Style.RESET_ALL} Usage: python AutoUnpackAHK.py <path_to_exe>")
        sys.exit(1)
    
    exe_path = sys.argv[1]
    
    if not os.path.exists(exe_path):
        print(f"{Fore.RED}[!]{Style.RESET_ALL} Error: File '{Fore.RED}{exe_path}{Style.RESET_ALL}' not found.")
        print(f"{Fore.RED}[!]{Style.RESET_ALL} Please provide the correct path to the executable file.")
        input("press [ENTER] to continue")
        sys.exit(1)
    
    script_data = extract_ahk_script(exe_path)
    
    if script_data:
        output_file = exe_path.split(".")[0] + ".ahk"
        
        compiler_version = extract_compiler_version(script_data)
        if compiler_version:
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Detected AutoHotkey compiler version: {Fore.CYAN}{compiler_version}{Style.RESET_ALL}")
        
        lines = script_data.split(b'\n')
        if lines and lines[0].startswith(b'; <COMPILER:'):
            script_data = b'\n'.join(lines[1:])
            print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Removed compiler directive from the first line")
        
        with open(output_file, "wb") as f:
            f.write(script_data)
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} AutoHotkey script successfully extracted to {Fore.RED}{output_file}{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}[-]{Style.RESET_ALL} No AutoHotkey script found in the executable.")

if __name__ == "__main__":
    os.system("cls")
    main()
    input("press [ENTER] to continue")

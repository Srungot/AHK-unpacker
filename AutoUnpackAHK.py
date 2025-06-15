import sys
import os
import pefile
import colorama
from colorama import Fore, Style

colorama.init()

def extract_ahk_script(exe_path):
    try:
        pe = pefile.PE(exe_path)
        
        print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Analyzing file: {Fore.RED}{exe_path}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Found {len(pe.sections)} sections in the PE file")
        
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
        sys.exit(1)
    
    script_data = extract_ahk_script(exe_path)
    
    if script_data:
        output_file = exe_path.split(".")[0] + ".ahk"
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
    main()
    input("press [ENTER] to continue")
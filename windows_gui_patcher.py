import os
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import sys
import shutil
import logging
import platform
import re
from typing import Optional, Tuple, List, Dict
from urllib.parse import urlparse
import requests

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("apk_patcher.log"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

# Constants
APKTOOL_VERSION = "2.10.0"
APKTOOL_JAR = f"apktool_{APKTOOL_VERSION}.jar"
DEPENDENCIES = {
    'java': 'Java (OpenJDK 11+)',
    'python': 'Python 3+'
}
VALID_ARCHS = ['armeabi-v7a', 'arm64-v8a']
BASE_CONFIG = {
    'sdk_tools_dir': 'android-sdk',
    'platform_tools_dir': 'platform-tools',
    'venv_dir': 'venv',
    'decompiled_dir': 'tappedout'
}

class APKPatcherError(Exception):
    """Custom exception for APK patching errors"""
    pass

def validate_url(url: str) -> bool:
    """Validate URL format"""
    try:
        result = urlparse(url)
        return all([result.scheme in ('http', 'https'), result.netloc])
    except ValueError:
        return False

def download_file(url: str, dest: str, timeout: int = 30) -> None:
    """Download a file with timeout and retries"""
    try:
        logger.info(f"Downloading {url} to {dest}")
        response = requests.get(url, stream=True, timeout=timeout)
        response.raise_for_status()
        
        with open(dest, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
        logger.info(f"Successfully downloaded {url}")
    except Exception as e:
        logger.error(f"Failed to download {url}: {e}")
        raise APKPatcherError(f"Download failed: {e}")

def check_dependencies() -> List[str]:
    """Check for required system dependencies"""
    missing = []
    for cmd, name in DEPENDENCIES.items():
        if not shutil.which(cmd):
            missing.append(name)
    return missing

def install_java() -> None:
    """Install Java dependencies"""
    try:
        if platform.system() == "Windows":
            raise APKPatcherError(
                "Please install OpenJDK 11+ manually and ensure it's in your PATH"
            )
        else:
            logger.info("Installing OpenJDK...")
            subprocess.run(
                ["sudo", "apt-get", "install", "-y", "openjdk-11-jre"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
    except subprocess.CalledProcessError as e:
        raise APKPatcherError(f"Java installation failed: {e}")

def setup_apktool() -> None:
    """Install and configure apktool"""
    try:
        if not os.path.isfile(APKTOOL_JAR):
            download_file(
                f"https://github.com/iBotPeaches/Apktool/releases/download/v{APKTOOL_VERSION}/{APKTOOL_JAR}",
                APKTOOL_JAR
            )
        
        wrapper_name = "apktool.bat" if platform.system() == "Windows" else "apktool"
        if not shutil.which(wrapper_name):
            wrapper_url = (
                "https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/windows/apktool.bat"
                if platform.system() == "Windows"
                else "https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool"
            )
            download_file(wrapper_url, wrapper_name)
            os.chmod(wrapper_name, 0o755)
    except Exception as e:
        raise APKPatcherError(f"Apktool setup failed: {e}")

def setup_venv() -> str:
    """Set up Python virtual environment with integrity checks"""
    venv_dir = BASE_CONFIG['venv_dir']
    pip_name = 'pip.exe' if platform.system() == 'Windows' else 'pip'
    pip_path = os.path.join(venv_dir, 'Scripts' if platform.system() == 'Windows' else 'bin', pip_name)

    # Check for existing venv integrity
    if os.path.exists(venv_dir):
        logger.info("Found existing virtual environment")
        if not os.path.exists(pip_path):
            logger.warning("Virtual environment appears corrupted - recreating...")
            try:
                shutil.rmtree(venv_dir)
            except Exception as e:
                raise APKPatcherError(f"Failed to remove corrupted venv: {e}")

    # Create fresh venv if needed
    if not os.path.exists(venv_dir):
        logger.info("Creating new virtual environment...")
        try:
            subprocess.run(
                [sys.executable, "-m", "venv", venv_dir],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        except subprocess.CalledProcessError as e:
            raise APKPatcherError(f"Virtual environment creation failed: {e}")

    # Final verification
    if not os.path.exists(pip_path):
        raise APKPatcherError("Virtual environment setup failed - pip not found")

    return pip_path

def install_python_deps(pip_path: str) -> None:
    """Install Python dependencies in virtual environment"""
    try:
        subprocess.run(
            [pip_path, "install", "buildapp"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        buildapp_tools = os.path.join(
            BASE_CONFIG['venv_dir'],
            'Scripts' if platform.system() == 'Windows' else 'bin',
            'buildapp_fetch_tools'
        )
        subprocess.run([buildapp_tools], check=True)
    except subprocess.CalledProcessError as e:
        raise APKPatcherError(f"Python dependency installation failed: {e}")

def decompile_apk(apk_path: str) -> None:
    """Decompile APK using apktool with overwrite handling"""
    output_dir = BASE_CONFIG['decompiled_dir']
    
    # Check if output directory exists
    if os.path.exists(output_dir):
        logger.warning(f"Output directory {output_dir} already exists")
        response = messagebox.askyesno(
            "Directory Exists",
            f"The output directory '{output_dir}' already exists.\n"
            "Do you want to delete it and continue?"
        )
        if not response:
            raise APKPatcherError("Decompilation cancelled by user")
        
        # Clean up existing directory
        try:
            logger.info(f"Removing existing directory: {output_dir}")
            shutil.rmtree(output_dir)
        except Exception as e:
            raise APKPatcherError(f"Failed to remove existing directory: {e}")

    # Perform decompilation
    try:
        logger.info(f"Decompiling {apk_path}...")
        subprocess.run(
            ["java", "-jar", APKTOOL_JAR, "d", apk_path, "-o", output_dir],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.decode().strip() if e.stderr else str(e)
        raise APKPatcherError(f"Decompilation failed: {error_msg}")

def replace_urls(replacements: Dict[str, str]) -> List[str]:
    """Replace URLs in decompiled files and return log"""
    log = []
    compiled_pattern = re.compile("|".join(map(re.escape, replacements.keys())))
    
    for root, _, files in os.walk(BASE_CONFIG['decompiled_dir']):
        for file in files:
            if not file.endswith((".xml", ".smali", ".txt")):
                continue
                
            file_path = os.path.join(root, file)
            try:
                with open(file_path, "r+", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    new_content, count = compiled_pattern.subn(
                        lambda m: replacements[m.group(0)], content
                    )
                    if count > 0:
                        f.seek(0)
                        f.truncate()
                        f.write(new_content)
                        log.append(f"Replaced {count} occurrence(s) in {file_path}")
                        # Log the URLs being replaced
                        for old_url, new_url in replacements.items():
                            if old_url in content:
                                logger.info(f"Replaced URL: {old_url} -> {new_url} in {file_path}")
            except Exception as e:
                logger.warning(f"Error processing {file_path}: {e}")
    
    return log

def binary_patch_so_files(new_url: str) -> None:
    """Patch URLs in compiled .so files"""
    original_url = b"http://oct2018-4-35-0-uam5h44a.tstodlc.eamobile.com/netstorage/gameasset/direct/simpsons/"
    new_url = new_url.rstrip("/") + "/static/"
    new_url_bytes = new_url.encode('utf-8')
    
    if len(new_url_bytes) > len(original_url):
        new_url_bytes = new_url_bytes[:len(original_url)]
    elif len(new_url_bytes) < len(original_url):
        padding = b'./' * ((len(original_url) - len(new_url_bytes)) // 2)
        new_url_bytes += padding + (b'/' if (len(original_url) - len(new_url_bytes)) % 2 else b'')
    
    for arch in VALID_ARCHS:
        for variant in ['', '-neon']:
            so_path = os.path.join(
                BASE_CONFIG['decompiled_dir'],
                'lib',
                arch,
                f'libscorpio{variant}.so'
            )
            if not os.path.exists(so_path):
                continue
                
            try:
                with open(so_path, 'r+b') as f:
                    content = f.read()
                    offset = content.find(original_url)
                    if offset == -1:
                        continue
                    f.seek(offset)
                    f.write(new_url_bytes)
                    logger.info(f"Patched {so_path}")
            except Exception as e:
                logger.error(f"Error patching {so_path}: {e}")

def recompile_apk(output_name: str) -> str:
    """Recompile patched APK"""
    try:
        buildapp_path = os.path.join(
            BASE_CONFIG['venv_dir'],
            'Scripts' if platform.system() == 'Windows' else 'bin',
            'buildapp'
        )
        subprocess.run(
            [buildapp_path, "-d", BASE_CONFIG['decompiled_dir'], "-o", output_name],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return output_name
    except subprocess.CalledProcessError as e:
        raise APKPatcherError(f"Recompilation failed: {e}")

class APKPatcherGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("APK Patcher")
        self.status_var = tk.StringVar()
        self.setup_ui()
        self.progress_bar = None        
        
        # Configure dark theme
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.configure_styles()

    def configure_styles(self):
        """Configure dark theme styles"""
        bg = "#2e2e2e"
        fg = "#ffffff"
        entry_bg = "#4a4a4a"
        
        self.style.configure(".", background=bg, foreground=fg)
        self.style.configure("TLabel", background=bg, foreground=fg)
        self.style.configure("TButton", background="#5a5a5a", foreground=fg)
        self.style.configure("TEntry", fieldbackground=entry_bg, foreground=fg)
        self.style.configure("TFrame", background=bg)
        self.style.map("TButton",
            background=[('active', '#6a6a6a'), ('disabled', '#4a4a4a')]
        )

    def setup_ui(self):
        """Initialize GUI components"""
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # APK File Selection
        ttk.Label(main_frame, text="APK File:").grid(row=0, column=0, sticky=tk.W)
        self.apk_entry = ttk.Entry(main_frame, width=50)
        self.apk_entry.grid(row=0, column=1, padx=5)
        ttk.Button(main_frame, text="Browse", command=self.browse_apk).grid(row=0, column=2, padx=5)

        # Server URLs
        ttk.Label(main_frame, text="Gameserver URL:").grid(row=1, column=0, sticky=tk.W)
        self.gameserver_entry = ttk.Entry(main_frame, width=50)
        self.gameserver_entry.grid(row=1, column=1, columnspan=2, pady=5)

        ttk.Label(main_frame, text="DLC Server URL:").grid(row=2, column=0, sticky=tk.W)
        self.dlcserver_entry = ttk.Entry(main_frame, width=50)
        self.dlcserver_entry.grid(row=2, column=1, columnspan=2, pady=5)

        # Progress and Status
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=3, column=0, columnspan=3, pady=10, sticky=tk.EW)
        
        self.status = ttk.Label(main_frame, textvariable=self.status_var)
        self.status.grid(row=4, column=0, columnspan=3, pady=5)

        # Action Buttons
        ttk.Button(main_frame, text="Check Dependencies", command=self.check_deps).grid(
            row=5, column=0, pady=5, sticky=tk.W
        )
        ttk.Button(main_frame, text="Patch APK", command=self.start_patching).grid(
            row=5, column=1, pady=5, sticky=tk.EW
        )
        ttk.Button(main_frame, text="Exit", command=self.root.quit).grid(
            row=5, column=2, pady=5, sticky=tk.E
        )

        # Footer
        ttk.Label(self.root, text="Bodnjenie™", anchor=tk.E).pack(
            side=tk.BOTTOM, fill=tk.X, padx=10, pady=5
        )

    def browse_apk(self):
        """Browse for APK file"""
        path = filedialog.askopenfilename(filetypes=[("APK files", "*.apk")])
        if path:
            self.apk_entry.delete(0, tk.END)
            self.apk_entry.insert(0, path)

    def check_deps(self):
        """Check system dependencies"""
        try:
            missing = check_dependencies()
            if missing:
                messagebox.showwarning(
                    "Missing Dependencies",
                    "Missing:\n" + "\n".join(missing) + "\n\nPlease install them first."
                )
            else:
                messagebox.showinfo("Dependencies", "All required dependencies are installed.")
        except Exception as e:
            self.show_error(f"Dependency check failed: {e}")

    def validate_inputs(self) -> Tuple[str, str, str]:
        """Validate user inputs and return cleaned values"""
        apk_path = self.apk_entry.get().strip()
        gameserver = self.gameserver_entry.get().strip()
        dlcserver = self.dlcserver_entry.get().strip()

        if not apk_path or not gameserver or not dlcserver:
            raise ValueError("All fields are required")
        
        if not os.path.isfile(apk_path):
            raise ValueError("Invalid APK file path")
        
        if not validate_url(gameserver):
            raise ValueError("Invalid Gameserver URL")
        
        if not validate_url(dlcserver):
            raise ValueError("Invalid DLC Server URL")
        
        return apk_path, gameserver, dlcserver.rstrip('/') + '/'

    def update_status(self, message: str):
        """Update status label"""
        self.status_var.set(message)
        self.root.update_idletasks()

    def show_error(self, message: str):
        """Show error message"""
        logger.error(message)
        messagebox.showerror("Error", message)
        self.progress.stop()

    def start_patching(self):
        """Start the APK patching process"""
        try:
            self.progress.start()
            apk_path, gameserver, dlcserver = self.validate_inputs()
            
            self.update_status("Installing dependencies...")
            missing_deps = check_dependencies()
            if missing_deps:
                install_java()
            
            setup_apktool()
            pip_path = setup_venv()
            install_python_deps(pip_path)

            self.update_status("Decompiling APK...")
            decompile_apk(apk_path)

            self.update_status("Patching text resources...")
            replace_log = replace_urls({
                "https://prod.simpsons-ea.com": gameserver,
                "https://syn-dir.sn.eamobile.com": gameserver
            })
            logger.info("\n".join(replace_log))

            self.update_status("Patching binary resources...")
            binary_patch_so_files(dlcserver)

            self.update_status("Recompiling APK...")
            output_name = f"{os.path.splitext(os.path.basename(apk_path))[0]}-patched.apk"
            output_path = recompile_apk(output_name)

            self.progress.stop()
            messagebox.showinfo("Success", f"Patched APK created:\n{output_path}")
            self.status_var.set("Ready")
            
        except Exception as e:
            self.show_error(str(e))
        finally:
            self.progress.stop()

if __name__ == "__main__":
    root = tk.Tk()
    app = APKPatcherGUI(root)
    root.mainloop()

# coded by @bodnjenie
# credit to @tjac for patching logic
# ai refactor by @hclivess

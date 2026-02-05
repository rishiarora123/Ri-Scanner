"""
Ri-Scanner Pro - Tools Checker & Installer

Provides functionality to:
- Check if tools are installed
- Check if API keys are configured
- Auto-install missing tools
- Report tool status
"""
import os
import subprocess
import shutil
import json
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from .tools_config import TOOLS, CATEGORIES, Tool, get_tools_by_category, get_all_required_api_keys


class ToolsChecker:
    """
    Handles checking tool availability and installation.
    """
    
    def __init__(self, settings_file: Optional[str] = None):
        """
        Initialize the tools checker.
        
        Args:
            settings_file: Path to settings JSON file (overrides .env)
        """
        self.settings_file = settings_file or "settings.json"
        self._settings_cache = None
        self._tool_status_cache = {}
    
    def get_settings(self) -> Dict[str, str]:
        """
        Get API key settings from settings file, falling back to .env variables.
        Settings file takes priority over .env.
        """
        if self._settings_cache is not None:
            return self._settings_cache
        
        settings = {}
        
        # First, load from .env file (if exists)
        env_file = Path(".env")
        if env_file.exists():
            with open(env_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, value = line.split("=", 1)
                        settings[key.strip()] = value.strip().strip('"').strip("'")
        
        # Then, load from system environment variables
        for key in get_all_required_api_keys().keys():
            if key in os.environ:
                settings[key] = os.environ[key]
        
        # Finally, override with settings file (highest priority)
        settings_path = Path(self.settings_file)
        if settings_path.exists():
            try:
                with open(settings_path, "r") as f:
                    file_settings = json.load(f)
                    # Only override non-empty values
                    for k, v in file_settings.items():
                        if v:  # Only if value is not empty
                            settings[k] = v
            except (json.JSONDecodeError, IOError):
                pass
        
        self._settings_cache = settings
        return settings
    
    def save_settings(self, new_settings: Dict[str, str]) -> bool:
        """
        Save API key settings to settings file.
        
        Args:
            new_settings: Dictionary of API key settings
            
        Returns:
            True if saved successfully
        """
        try:
            # Load existing settings
            settings_path = Path(self.settings_file)
            existing = {}
            if settings_path.exists():
                with open(settings_path, "r") as f:
                    existing = json.load(f)
            
            # Merge with new settings
            existing.update(new_settings)
            
            # Save
            with open(settings_path, "w") as f:
                json.dump(existing, f, indent=2)
            
            # Clear cache
            self._settings_cache = None
            return True
        except Exception as e:
            print(f"Error saving settings: {e}")
            return False
    
    def check_tool_installed(self, tool: Tool) -> Tuple[bool, str]:
        """
        Check if a specific tool is installed.
        
        Args:
            tool: Tool to check
            
        Returns:
            Tuple of (is_installed, version_or_error)
        """
        if tool.is_api_only:
            return (True, "API-only (no CLI needed)")
        
        if not tool.check_cmd:
            return (False, "No check command defined")
        
        # Use cached result if available
        cache_key = tool.id
        if cache_key in self._tool_status_cache:
            return self._tool_status_cache[cache_key]
        
        try:
            # First check if command exists in PATH
            cmd = tool.check_cmd[0]
            if not shutil.which(cmd):
                result = (False, "Not found in PATH")
                self._tool_status_cache[cache_key] = result
                return result
            
            # Try running the check command
            proc = subprocess.run(
                tool.check_cmd,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if proc.returncode == 0:
                # Extract version from output (first line usually)
                version = proc.stdout.strip().split('\n')[0][:50] if proc.stdout else "Installed"
                result = (True, version)
            else:
                # Some tools return non-zero for --help, but still exist
                result = (True, "Installed")
            
            self._tool_status_cache[cache_key] = result
            return result
            
        except subprocess.TimeoutExpired:
            result = (True, "Installed (timeout on version check)")
            self._tool_status_cache[cache_key] = result
            return result
        except FileNotFoundError:
            result = (False, "Not installed")
            self._tool_status_cache[cache_key] = result
            return result
        except Exception as e:
            result = (False, str(e))
            self._tool_status_cache[cache_key] = result
            return result
    
    def check_api_keys(self, tool: Tool) -> Tuple[bool, List[str]]:
        """
        Check if required API keys are configured for a tool.
        
        Args:
            tool: Tool to check
            
        Returns:
            Tuple of (all_keys_present, list_of_missing_keys)
        """
        if not tool.requires_api:
            return (True, [])
        
        settings = self.get_settings()
        missing = []
        
        for key in tool.api_keys:
            if key not in settings or not settings[key]:
                missing.append(key)
        
        return (len(missing) == 0, missing)
    
    def get_full_status(self) -> Dict[str, Any]:
        """
        Get complete status of all tools.
        
        Returns:
            Dictionary with categories, tools status, and summary
        """
        status = {
            "categories": {},
            "summary": {
                "total": len(TOOLS),
                "installed": 0,
                "api_ready": 0,
                "missing_cli": 0,
                "missing_api_keys": 0
            },
            "missing_api_keys": []
        }
        
        grouped = get_tools_by_category()
        
        for cat_id, tools in grouped.items():
            cat_info = CATEGORIES.get(cat_id, {"name": cat_id, "icon": "🔧"})
            cat_status = {
                "name": cat_info["name"],
                "icon": cat_info["icon"],
                "tools": []
            }
            
            for tool in tools:
                is_installed, version = self.check_tool_installed(tool)
                api_ok, missing_keys = self.check_api_keys(tool)
                
                tool_status = {
                    "id": tool.id,
                    "name": tool.name,
                    "description": tool.description,
                    "installed": is_installed,
                    "version": version,
                    "requires_api": tool.requires_api,
                    "api_configured": api_ok,
                    "missing_api_keys": missing_keys,
                    "is_api_only": tool.is_api_only,
                    "install_cmds": tool.install_cmds,
                    "api_url": tool.api_url,
                    "requires_root": tool.requires_root
                }
                cat_status["tools"].append(tool_status)
                
                # Update summary
                if is_installed:
                    status["summary"]["installed"] += 1
                else:
                    status["summary"]["missing_cli"] += 1
                
                if tool.requires_api and api_ok:
                    status["summary"]["api_ready"] += 1
                elif tool.requires_api and not api_ok:
                    status["summary"]["missing_api_keys"] += 1
                    for key in missing_keys:
                        if key not in status["missing_api_keys"]:
                            status["missing_api_keys"].append(key)
            
            status["categories"][cat_id] = cat_status
        
        return status
    
    def install_tool(self, tool_id: str, package_manager: str = "auto") -> Tuple[bool, str]:
        """
        Attempt to install a tool.
        
        Args:
            tool_id: ID of tool to install
            package_manager: Which package manager to use (auto, brew, go, pip, etc.)
            
        Returns:
            Tuple of (success, message)
        """
        tool = TOOLS.get(tool_id)
        if not tool:
            return (False, f"Unknown tool: {tool_id}")
        
        if tool.is_api_only:
            return (True, "API-only tool, no installation needed")
        
        if not tool.install_cmds:
            return (False, "No install command available")
        
        # Determine which package manager to use
        if package_manager == "auto":
            # Priority order: brew (macOS), go, pip, apt, cargo, git
            priority = ["brew", "go", "pip", "apt", "cargo", "git"]
            for pm in priority:
                if pm in tool.install_cmds:
                    # Check if package manager is available
                    if shutil.which(pm) or (pm == "git" and shutil.which("git")):
                        package_manager = pm
                        break
            else:
                return (False, "No suitable package manager found")
        
        if package_manager not in tool.install_cmds:
            return (False, f"No install command for {package_manager}")
        
        install_cmd = tool.install_cmds[package_manager]
        
        try:
            # Run install command
            proc = subprocess.run(
                install_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if proc.returncode == 0:
                # Clear cache to force re-check
                self._tool_status_cache.pop(tool_id, None)
                return (True, f"Successfully installed {tool.name}")
            else:
                return (False, f"Install failed: {proc.stderr[:200]}")
                
        except subprocess.TimeoutExpired:
            return (False, "Installation timed out")
        except Exception as e:
            return (False, f"Install error: {str(e)}")
    
    def get_install_instructions(self, tool_id: str) -> Dict[str, str]:
        """
        Get installation instructions for a tool.
        
        Args:
            tool_id: Tool ID
            
        Returns:
            Dictionary with package manager -> install command
        """
        tool = TOOLS.get(tool_id)
        if not tool:
            return {}
        return tool.install_cmds
    
    def clear_cache(self):
        """Clear all cached data."""
        self._tool_status_cache = {}
        self._settings_cache = None


# Singleton instance
_checker_instance: Optional[ToolsChecker] = None


def get_tools_checker() -> ToolsChecker:
    """Get or create the global ToolsChecker instance."""
    global _checker_instance
    if _checker_instance is None:
        _checker_instance = ToolsChecker()
    return _checker_instance

#!/usr/bin/env python3
"""
VEnv-Master: Sistema Avanzado de Gestión de Entornos Virtuales
Arquitectura cognitiva para la administración inteligente de entornos Python
"""

import os
import subprocess
import sys
import json
import shutil
import hashlib
import tarfile
import tempfile
import platform
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Union
import configparser

class VEnvMasterCore:
    """
    Núcleo arquitectónico para la gestión avanzada de entornos virtuales.
    Implementa patrones de diseño resilientes y algoritmos adaptativos.
    """
    
    def __init__(self):
        self.system_platform = platform.system().lower()
        self.base_dir = Path.home() / ".venv-master"
        self.venv_dir = self.base_dir / "environments"
        self.backup_dir = self.base_dir / "backups"
        self.config_file = self.base_dir / "config.json"
        self.metadata_file = self.base_dir / "metadata.json"
        
        # Inicialización de arquitectura
        self._initialize_architecture()
        self._load_configuration()
        self._load_metadata()
    
    def _initialize_architecture(self):
        """Construcción de la arquitectura base del sistema."""
        directories = [self.base_dir, self.venv_dir, self.backup_dir]
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
        
        if not self.config_file.exists():
            self._create_default_config()
    
    def _create_default_config(self):
        """Generación de configuración adaptativa por defecto."""
        default_config = {
            "default_python_version": "3.11",
            "backup_retention_days": 30,
            "auto_backup_on_destroy": True,
            "compression_level": 6,
            "supported_managers": ["venv", "virtualenv", "conda"],
            "audit_mode": "comprehensive",
            "diagnostic_verbosity": "detailed"
        }
        
        with open(self.config_file, 'w') as f:
            json.dump(default_config, f, indent=2)
        
        self.config = default_config
    
    def _load_configuration(self):
        """Carga dinámica de configuración del sistema."""
        try:
            with open(self.config_file, 'r') as f:
                self.config = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self._create_default_config()
    
    def _load_metadata(self):
        """Gestión de metadatos de entornos virtuales."""
        try:
            with open(self.metadata_file, 'r') as f:
                self.metadata = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self.metadata = {}
    
    def _save_metadata(self):
        """Persistencia de metadatos del sistema."""
        with open(self.metadata_file, 'w') as f:
            json.dump(self.metadata, f, indent=2)
    
    def _generate_environment_signature(self, venv_path: Path) -> str:
        """Generación de firma criptográfica para integridad de entornos."""
        signature_data = []
        
        # Análisis de estructura del entorno
        for root, dirs, files in os.walk(venv_path):
            for file in files:
                file_path = Path(root) / file
                try:
                    signature_data.append(f"{file_path.relative_to(venv_path)}")
                except ValueError:
                    continue
        
        # Generación de hash SHA-256
        signature_string = "|".join(sorted(signature_data))
        return hashlib.sha256(signature_string.encode()).hexdigest()[:16]
    
    def create_environment(self, name: str, manager: str = "venv", 
                          python_version: Optional[str] = None) -> bool:
        """
        Creación avanzada de entornos virtuales con patrones adaptativos.
        
        Args:
            name: Identificador único del entorno
            manager: Gestor de entornos (venv, virtualenv, conda)
            python_version: Versión específica de Python
        
        Returns:
            bool: Estado de éxito de la operación
        """
        try:
            venv_path = self.venv_dir / name
            
            if venv_path.exists():
                print(f"❌ Entorno '{name}' ya existe en el sistema")
                return False
            
            # Selección inteligente de versión Python
            if not python_version:
                python_version = self.config.get("default_python_version", "3.11")
            
            creation_timestamp = datetime.now().isoformat()
            
            # Algoritmo de creación según el gestor
            success = self._execute_creation_algorithm(name, venv_path, manager, python_version)
            
            if success:
                # Registro de metadatos
                signature = self._generate_environment_signature(venv_path)
                self.metadata[name] = {
                    "created": creation_timestamp,
                    "manager": manager,
                    "python_version": python_version,
                    "signature": signature,
                    "last_used": creation_timestamp,
                    "status": "active"
                }
                self._save_metadata()
                
                print(f"✅ Entorno '{name}' creado exitosamente")
                print(f"📊 Gestor: {manager} | Python: {python_version}")
                print(f"🔐 Firma: {signature}")
                return True
            
            return False
            
        except Exception as e:
            print(f"❌ Error en creación de entorno '{name}': {str(e)}")
            return False
    
    def _execute_creation_algorithm(self, name: str, venv_path: Path, 
                                   manager: str, python_version: str) -> bool:
        """Algoritmo especializado de creación por gestor."""
        try:
            if manager == "venv":
                # Búsqueda inteligente del intérprete Python
                python_executable = self._find_python_executable(python_version)
                if not python_executable:
                    print(f"❌ Python {python_version} no encontrado")
                    return False
                
                subprocess.run([python_executable, "-m", "venv", str(venv_path)], 
                             check=True, capture_output=True)
                
            elif manager == "virtualenv":
                subprocess.run(["virtualenv", "-p", f"python{python_version}", 
                              str(venv_path)], check=True, capture_output=True)
                
            elif manager == "conda":
                subprocess.run(["conda", "create", "--prefix", str(venv_path), 
                              f"python={python_version}", "-y"], 
                             check=True, capture_output=True)
            else:
                print(f"❌ Gestor '{manager}' no implementado")
                return False
            
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Error en proceso de creación: {e}")
            return False
        except FileNotFoundError:
            print(f"❌ Gestor '{manager}' no disponible en el sistema")
            return False
    
    def _find_python_executable(self, version: str) -> Optional[str]:
        """Búsqueda inteligente de ejecutables Python."""
        possible_names = [
            f"python{version}",
            f"python{version.split('.')[0]}.{version.split('.')[1]}",
            f"python{version.split('.')[0]}",
            "python3",
            "python"
        ]
        
        for name in possible_names:
            if shutil.which(name):
                return name
        
        return None
    
    def destroy_environment(self, name: str, backup: bool = None) -> bool:
        """
        Destrucción controlada de entornos con patrones de seguridad.
        
        Args:
            name: Identificador del entorno
            backup: Realizar backup antes de destruir
        
        Returns:
            bool: Estado de éxito de la operación
        """
        try:
            venv_path = self.venv_dir / name
            
            if not venv_path.exists():
                print(f"❌ Entorno '{name}' no encontrado")
                return False
            
            # Política de backup automático
            if backup is None:
                backup = self.config.get("auto_backup_on_destroy", True)
            
            if backup:
                print(f"📦 Creando backup de seguridad...")
                backup_success = self.backup_environment(name)
                if not backup_success:
                    print("⚠️  Falló el backup, continuando con destrucción...")
            
            # Eliminación segura del entorno
            shutil.rmtree(venv_path)
            
            # Actualización de metadatos
            if name in self.metadata:
                self.metadata[name]["status"] = "destroyed"
                self.metadata[name]["destroyed"] = datetime.now().isoformat()
                self._save_metadata()
            
            print(f"✅ Entorno '{name}' eliminado exitosamente")
            return True
            
        except Exception as e:
            print(f"❌ Error eliminando entorno '{name}': {str(e)}")
            return False
    
    def activate_environment(self, name: str) -> bool:
        """
        Activación inteligente de entornos virtuales multiplataforma.
        
        Args:
            name: Identificador del entorno
        
        Returns:
            bool: Estado de éxito de la operación
        """
        try:
            venv_path = self.venv_dir / name
            
            if not venv_path.exists():
                print(f"❌ Entorno '{name}' no encontrado")
                return False
            
            # Detección de scripts de activación por plataforma
            if self.system_platform == "windows":
                activate_script = venv_path / "Scripts" / "activate.bat"
                powershell_script = venv_path / "Scripts" / "Activate.ps1"
                
                if activate_script.exists():
                    print(f"🚀 Activando entorno '{name}'...")
                    print(f"💻 Ejecutar: {activate_script}")
                elif powershell_script.exists():
                    print(f"🚀 Activando entorno '{name}' (PowerShell)...")
                    print(f"💻 Ejecutar: {powershell_script}")
                else:
                    print(f"❌ Scripts de activación no encontrados")
                    return False
            else:
                activate_script = venv_path / "bin" / "activate"
                if activate_script.exists():
                    print(f"🚀 Activando entorno '{name}'...")
                    print(f"💻 Ejecutar: source {activate_script}")
                else:
                    print(f"❌ Script de activación no encontrado")
                    return False
            
            # Actualización de metadatos de uso
            if name in self.metadata:
                self.metadata[name]["last_used"] = datetime.now().isoformat()
                self._save_metadata()
            
            return True
            
        except Exception as e:
            print(f"❌ Error activando entorno '{name}': {str(e)}")
            return False
    
    def list_environments(self, detailed: bool = False) -> List[Dict]:
        """
        Enumeración avanzada de entornos con análisis detallado.
        
        Args:
            detailed: Mostrar información detallada
        
        Returns:
            List[Dict]: Lista de entornos con metadatos
        """
        try:
            environments = []
            
            if not self.venv_dir.exists():
                print("📂 No se encontraron entornos virtuales")
                return environments
            
            for env_path in self.venv_dir.iterdir():
                if env_path.is_dir():
                    env_name = env_path.name
                    env_info = {
                        "name": env_name,
                        "path": str(env_path),
                        "size": self._calculate_directory_size(env_path)
                    }
                    
                    # Integración de metadatos
                    if env_name in self.metadata:
                        env_info.update(self.metadata[env_name])
                    
                    environments.append(env_info)
            
            # Visualización de entornos
            if environments:
                print("🐍 Entornos Virtuales Disponibles:")
                print("=" * 50)
                
                for env in sorted(environments, key=lambda x: x.get("created", "")):
                    status_icon = "🟢" if env.get("status") == "active" else "🔴"
                    print(f"{status_icon} {env['name']}")
                    
                    if detailed:
                        print(f"   📍 Ruta: {env['path']}")
                        print(f"   📊 Tamaño: {self._format_size(env['size'])}")
                        print(f"   🐍 Python: {env.get('python_version', 'N/A')}")
                        print(f"   ⚙️  Gestor: {env.get('manager', 'N/A')}")
                        print(f"   📅 Creado: {env.get('created', 'N/A')}")
                        print(f"   🔄 Último uso: {env.get('last_used', 'N/A')}")
                        print(f"   🔐 Firma: {env.get('signature', 'N/A')}")
                        print()
            else:
                print("📭 No se encontraron entornos virtuales")
            
            return environments
            
        except Exception as e:
            print(f"❌ Error listando entornos: {str(e)}")
            return []
    
    def backup_environment(self, name: str) -> bool:
        """
        Sistema de backup avanzado con compresión adaptativa.
        
        Args:
            name: Identificador del entorno
        
        Returns:
            bool: Estado de éxito del backup
        """
        try:
            venv_path = self.venv_dir / name
            
            if not venv_path.exists():
                print(f"❌ Entorno '{name}' no encontrado")
                return False
            
            # Generación de nombre de backup temporal
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"{name}_{timestamp}.tar.gz"
            backup_path = self.backup_dir / backup_name
            
            # Proceso de compresión avanzada
            compression_level = self.config.get("compression_level", 6)
            
            with tarfile.open(backup_path, "w:gz", compresslevel=compression_level) as tar:
                tar.add(venv_path, arcname=name)
            
            # Registro de backup en metadatos
            if name not in self.metadata:
                self.metadata[name] = {}
            
            if "backups" not in self.metadata[name]:
                self.metadata[name]["backups"] = []
            
            backup_info = {
                "timestamp": timestamp,
                "file": backup_name,
                "size": backup_path.stat().st_size,
                "compression_level": compression_level
            }
            
            self.metadata[name]["backups"].append(backup_info)
            self._save_metadata()
            
            print(f"✅ Backup de '{name}' completado")
            print(f"📦 Archivo: {backup_name}")
            print(f"📊 Tamaño: {self._format_size(backup_info['size'])}")
            
            # Limpieza de backups antiguos
            self._cleanup_old_backups(name)
            
            return True
            
        except Exception as e:
            print(f"❌ Error creando backup de '{name}': {str(e)}")
            return False
    
    def restore_environment(self, name: str, backup_timestamp: Optional[str] = None) -> bool:
        """
        Restauración inteligente desde backups con verificación de integridad.
        
        Args:
            name: Identificador del entorno
            backup_timestamp: Timestamp específico del backup
        
        Returns:
            bool: Estado de éxito de la restauración
        """
        try:
            # Selección de backup
            if name not in self.metadata or "backups" not in self.metadata[name]:
                print(f"❌ No se encontraron backups para '{name}'")
                return False
            
            backups = self.metadata[name]["backups"]
            if not backups:
                print(f"❌ No hay backups disponibles para '{name}'")
                return False
            
            # Selección del backup más reciente o específico
            if backup_timestamp:
                selected_backup = next((b for b in backups if b["timestamp"] == backup_timestamp), None)
                if not selected_backup:
                    print(f"❌ Backup con timestamp '{backup_timestamp}' no encontrado")
                    return False
            else:
                selected_backup = max(backups, key=lambda x: x["timestamp"])
            
            backup_file = self.backup_dir / selected_backup["file"]
            
            if not backup_file.exists():
                print(f"❌ Archivo de backup no encontrado: {backup_file}")
                return False
            
            venv_path = self.venv_dir / name
            
            # Eliminación del entorno existente si existe
            if venv_path.exists():
                print(f"🗑️  Eliminando entorno existente...")
                shutil.rmtree(venv_path)
            
            # Restauración desde backup
            print(f"📦 Restaurando desde backup: {selected_backup['file']}")
            
            with tarfile.open(backup_file, "r:gz") as tar:
                tar.extractall(self.venv_dir)
            
            # Actualización de metadatos
            self.metadata[name]["status"] = "active"
            self.metadata[name]["restored"] = datetime.now().isoformat()
            self.metadata[name]["restored_from"] = selected_backup["timestamp"]
            self._save_metadata()
            
            print(f"✅ Entorno '{name}' restaurado exitosamente")
            print(f"📅 Desde backup: {selected_backup['timestamp']}")
            
            return True
            
        except Exception as e:
            print(f"❌ Error restaurando entorno '{name}': {str(e)}")
            return False
    
    def audit_environment(self, name: str) -> Dict:
        """
        Auditoría comprehensiva de entornos virtuales.
        
        Args:
            name: Identificador del entorno
        
        Returns:
            Dict: Reporte de auditoría detallado
        """
        try:
            venv_path = self.venv_dir / name
            
            if not venv_path.exists():
                print(f"❌ Entorno '{name}' no encontrado")
                return {}
            
            audit_report = {
                "environment": name,
                "audit_timestamp": datetime.now().isoformat(),
                "structure_analysis": {},
                "package_analysis": {},
                "security_analysis": {},
                "performance_metrics": {}
            }
            
            print(f"🔍 Iniciando auditoría de '{name}'...")
            
            # Análisis de estructura
            structure_analysis = self._analyze_environment_structure(venv_path)
            audit_report["structure_analysis"] = structure_analysis
            
            # Análisis de paquetes
            package_analysis = self._analyze_installed_packages(venv_path)
            audit_report["package_analysis"] = package_analysis
            
            # Análisis de seguridad
            security_analysis = self._analyze_security_vulnerabilities(venv_path)
            audit_report["security_analysis"] = security_analysis
            
            # Métricas de rendimiento
            performance_metrics = self._calculate_performance_metrics(venv_path)
            audit_report["performance_metrics"] = performance_metrics
            
            # Generación de reporte
            self._generate_audit_report(audit_report)
            
            return audit_report
            
        except Exception as e:
            print(f"❌ Error en auditoría de '{name}': {str(e)}")
            return {}
    
    def diagnose_environment(self, name: str) -> Dict:
        """
        Diagnóstico avanzado del estado del entorno virtual.
        
        Args:
            name: Identificador del entorno
        
        Returns:
            Dict: Reporte de diagnóstico
        """
        try:
            venv_path = self.venv_dir / name
            
            if not venv_path.exists():
                print(f"❌ Entorno '{name}' no encontrado")
                return {}
            
            diagnostic_report = {
                "environment": name,
                "diagnostic_timestamp": datetime.now().isoformat(),
                "health_status": "unknown",
                "issues_found": [],
                "recommendations": [],
                "integrity_check": {},
                "compatibility_check": {}
            }
            
            print(f"🩺 Iniciando diagnóstico de '{name}'...")
            
            # Verificación de integridad
            integrity_status = self._check_environment_integrity(venv_path, name)
            diagnostic_report["integrity_check"] = integrity_status
            
            # Verificación de compatibilidad
            compatibility_status = self._check_system_compatibility(venv_path)
            diagnostic_report["compatibility_check"] = compatibility_status
            
            # Detección de problemas
            issues = self._detect_environment_issues(venv_path)
            diagnostic_report["issues_found"] = issues
            
            # Generación de recomendaciones
            recommendations = self._generate_recommendations(issues, integrity_status, compatibility_status)
            diagnostic_report["recommendations"] = recommendations
            
            # Determinación del estado de salud
            health_status = self._determine_health_status(issues, integrity_status)
            diagnostic_report["health_status"] = health_status
            
            # Visualización del diagnóstico
            self._display_diagnostic_report(diagnostic_report)
            
            return diagnostic_report
            
        except Exception as e:
            print(f"❌ Error en diagnóstico de '{name}': {str(e)}")
            return {}
    
    # Métodos auxiliares para análisis y diagnóstico
    
    def _analyze_environment_structure(self, venv_path: Path) -> Dict:
        """Análisis de la estructura del entorno virtual."""
        structure = {
            "total_files": 0,
            "total_directories": 0,
            "python_executables": [],
            "key_directories": {},
            "missing_components": []
        }
        
        try:
            for root, dirs, files in os.walk(venv_path):
                structure["total_directories"] += len(dirs)
                structure["total_files"] += len(files)
                
                # Detección de ejecutables Python
                for file in files:
                    if file.startswith("python") and os.access(Path(root) / file, os.X_OK):
                        structure["python_executables"].append(str(Path(root) / file))
            
            # Verificación de directorios clave
            key_dirs = ["bin", "lib", "include", "Scripts", "Lib"]
            for key_dir in key_dirs:
                dir_path = venv_path / key_dir
                if dir_path.exists():
                    structure["key_directories"][key_dir] = {
                        "exists": True,
                        "size": self._calculate_directory_size(dir_path)
                    }
                else:
                    structure["missing_components"].append(key_dir)
            
        except Exception as e:
            structure["error"] = str(e)
        
        return structure
    
    def _analyze_installed_packages(self, venv_path: Path) -> Dict:
        """Análisis de paquetes instalados en el entorno."""
        package_analysis = {
            "total_packages": 0,
            "packages": [],
            "outdated_packages": [],
            "dependency_conflicts": []
        }
        
        try:
            # Detección del pip en el entorno
            if self.system_platform == "windows":
                pip_path = venv_path / "Scripts" / "pip.exe"
            else:
                pip_path = venv_path / "bin" / "pip"
            
            if pip_path.exists():
                # Lista de paquetes instalados
                result = subprocess.run([str(pip_path), "list", "--format=json"], 
                                      capture_output=True, text=True)
                
                if result.returncode == 0:
                    packages = json.loads(result.stdout)
                    package_analysis["total_packages"] = len(packages)
                    package_analysis["packages"] = packages
                
                # Paquetes desactualizados
                outdated_result = subprocess.run([str(pip_path), "list", "--outdated", "--format=json"], 
                                               capture_output=True, text=True)
                
                if outdated_result.returncode == 0:
                    outdated_packages = json.loads(outdated_result.stdout)
                    package_analysis["outdated_packages"] = outdated_packages
            
        except Exception as e:
            package_analysis["error"] = str(e)
        
        return package_analysis
    
    def _analyze_security_vulnerabilities(self, venv_path: Path) -> Dict:
        """Análisis de vulnerabilidades de seguridad."""
        security_analysis = {
            "vulnerability_scan": "basic",
            "potential_issues": [],
            "security_score": 0
        }
        
        try:
            # Verificación básica de permisos
            if not os.access(venv_path, os.R_OK):
                security_analysis["potential_issues"].append("Permisos de lectura restringidos")
            
            if not os.access(venv_path, os.W_OK):
                security_analysis["potential_issues"].append("Permisos de escritura restringidos")
            
            # Puntuación básica de seguridad
            security_score = 100 - (len(security_analysis["potential_issues"]) * 20)
            security_analysis["security_score"] = max(0, security_score)
            
        except Exception as e:
            security_analysis["error"] = str(e)
        
        return security_analysis
    
    def _calculate_performance_metrics(self, venv_path: Path) -> Dict:
        """Cálculo de métricas de rendimiento."""
        metrics = {
            "disk_usage": self._calculate_directory_size(venv_path),
            "file_count": 0,
            "startup_time_estimate": 0,
            "efficiency_score": 0
        }
        
        try:
            # Conteo de archivos
            file_count = sum(len(files) for _, _, files in os.walk(venv_path))
            metrics["file_count"] = file_count
            
            # Estimación de tiempo de inicio (heurística)
            startup_estimate = (file_count / 1000) * 0.1  # Segundos estimados
            metrics["startup_time_estimate"] = round(startup_estimate, 2)
            
            # Puntuación de eficiencia
            size_mb = metrics["disk_usage"] / (1024 * 1024)
            if size_mb < 50:
                efficiency_score = 100
            elif size_mb < 200:
                efficiency_score = 80
            elif size_mb < 500:
                efficiency_score = 60
            else:
                efficiency_score = 40
            
            metrics["efficiency_score"] = efficiency_score
            
        except Exception as e:
            metrics["error"] = str(e)
        
        return metrics
    
    def _check_environment_integrity(self, venv_path: Path, name: str) -> Dict:
        """Verificación de integridad del entorno."""
        integrity_check = {
            "signature_match": False,
            "structure_intact": True,
            "corruption_detected": False,
            "integrity_score": 0
        }
        
        try:
            # Verificación de firma si existe en metadatos
            if name in self.metadata and "signature" in self.metadata[name]:
                current_signature = self._generate_environment_signature(venv_path)
                original_signature = self.metadata[name]["signature"]
                
                integrity_check["signature_match"] = (current_signature == original_signature)
                integrity_check["current_signature"] = current_signature
                integrity_check["original_signature"] = original_signature
            
            # Verificación de estructura básica
            essential_components = ["pyvenv.cfg"]
            for component in essential_components:
                if not (venv_path / component).exists():
                    integrity_check["structure_intact"] = False
                    break
            
            # Cálculo de puntuación de integridad
            score = 100
            if not integrity_check["signature_match"]:
                score -= 30
            if not integrity_check["structure_intact"]:
                score -= 50
            
            integrity_check["integrity_score"] = max(0, score)
            
        except Exception as e:
            integrity_check["error"] = str(e)
        
        return integrity_check
    
    def _check_system_compatibility(self, venv_path: Path) -> Dict:
        """Verificación de compatibilidad del sistema."""
        compatibility = {
            "python_compatible": True,
            "platform_compatible": True,
            "architecture_compatible": True,
            "compatibility_score": 100
        }
        
        try:
            # Verificación de configuración del entorno
            pyvenv_cfg = venv_path / "pyvenv.cfg"
            if pyvenv_cfg.exists():
                config = configparser.ConfigParser()
                with open(pyvenv_cfg, 'r') as f:
                    config.read_string("[DEFAULT]\n" + f.read())
                
                # Verificación de Python base
                home_path = config.get("DEFAULT", "home", fallback="")
                if home_path and not Path(home_path).exists():
                    compatibility["python_compatible"] = False
                    compatibility["compatibility_score"] -= 40
            
        except Exception as e:
            compatibility["error"] = str(e)
        
        return compatibility
    
    def _detect_environment_issues(self, venv_path: Path) -> List[Dict]:
        """Detección de problemas en el entorno."""
        issues = []
        
        try:
            # Verificación de ejecutables Python
            python_executables = []
            for root, dirs, files in os.walk(venv_path):
                for file in files:
                    if file.startswith("python") and os.access(Path(root) / file, os.X_OK):
                        python_executables.append(Path(root) / file)
            
            if not python_executables:
                issues.append({
                    "type": "critical",
                    "description": "No se encontraron ejecutables Python",
                    "impact": "high",
                    "solution": "Recrear el entorno virtual"
                })
            
            # Verificación de pip
            pip_exists = False
            for root, dirs, files in os.walk(venv_path):
                if "pip" in files or "pip.exe" in files:
                    pip_exists = True
                    break
            
            if not pip_exists:
                issues.append({
                    "type": "warning",
                    "description": "Pip no encontrado en el entorno",
                    "impact": "medium",
                    "solution": "Reinstalar pip con: python -m ensurepip"
                })
            
            # Verificación de tamaño excesivo
            size = self._calculate_directory_size(venv_path)
            if size > 1024 * 1024 * 1024:  # 1GB
                issues.append({
                    "type": "warning",
                    "description": f"Entorno excesivamente grande ({self._format_size(size)})",
                    "impact": "low",
                    "solution": "Considerar limpieza de cache y paquetes innecesarios"
                })
            
        except Exception as e:
            issues.append({
                "type": "error",
                "description": f"Error durante detección de problemas: {str(e)}",
                "impact": "unknown",
                "solution": "Revisar manualmente el entorno"
            })
        
        return issues
    
    def _generate_recommendations(self, issues: List[Dict], integrity: Dict, compatibility: Dict) -> List[str]:
        """Generación de recomendaciones basadas en el análisis."""
        recommendations = []
        
        # Recomendaciones basadas en problemas detectados
        critical_issues = [issue for issue in issues if issue["type"] == "critical"]
        if critical_issues:
            recommendations.append("🚨 Recrear el entorno virtual debido a problemas críticos")
        
        # Recomendaciones de integridad
        if not integrity.get("signature_match", True):
            recommendations.append("🔧 Verificar integridad del entorno - posibles modificaciones no autorizadas")
        
        if not integrity.get("structure_intact", True):
            recommendations.append("🔧 Reparar estructura del entorno virtual")
        
        # Recomendaciones de compatibilidad
        if not compatibility.get("python_compatible", True):
            recommendations.append("🐍 Actualizar referencias de Python en el entorno")
        
        # Recomendaciones generales
        warning_issues = [issue for issue in issues if issue["type"] == "warning"]
        if len(warning_issues) > 2:
            recommendations.append("⚠️ Considerar mantenimiento preventivo del entorno")
        
        if not recommendations:
            recommendations.append("✅ Entorno en buen estado - no se requieren acciones")
        
        return recommendations
    
    def _determine_health_status(self, issues: List[Dict], integrity: Dict) -> str:
        """Determinación del estado de salud del entorno."""
        critical_issues = [issue for issue in issues if issue["type"] == "critical"]
        warning_issues = [issue for issue in issues if issue["type"] == "warning"]
        
        if critical_issues:
            return "critical"
        elif len(warning_issues) > 3 or not integrity.get("structure_intact", True):
            return "warning"
        elif warning_issues:
            return "caution"
        else:
            return "healthy"
    
    def _display_diagnostic_report(self, report: Dict):
        """Visualización del reporte de diagnóstico."""
        print(f"\n🩺 Reporte de Diagnóstico: {report['environment']}")
        print("=" * 60)
        
        # Estado de salud
        health_icons = {
            "healthy": "💚",
            "caution": "💛",
            "warning": "🟠",
            "critical": "🔴"
        }
        
        health_status = report["health_status"]
        print(f"{health_icons.get(health_status, '❓')} Estado de Salud: {health_status.upper()}")
        
        # Verificación de integridad
        integrity = report["integrity_check"]
        integrity_score = integrity.get("integrity_score", 0)
        print(f"🔐 Puntuación de Integridad: {integrity_score}/100")
        
        # Problemas encontrados
        issues = report["issues_found"]
        if issues:
            print(f"\n⚠️ Problemas Detectados ({len(issues)}):")
            for issue in issues:
                print(f"   • {issue['description']} ({issue['type']})")
        
        # Recomendaciones
        recommendations = report["recommendations"]
        if recommendations:
            print(f"\n💡 Recomendaciones:")
            for rec in recommendations:
                print(f"   • {rec}")
        
        print()
    
    def _generate_audit_report(self, report: Dict):
        """Generación de reporte de auditoría."""
        print(f"\n🔍 Reporte de Auditoría: {report['environment']}")
        print("=" * 60)
        
        # Análisis de estructura
        structure = report["structure_analysis"]
        print(f"📁 Análisis de Estructura:")
        print(f"   • Archivos: {structure.get('total_files', 0)}")
        print(f"   • Directorios: {structure.get('total_directories', 0)}")
        print(f"   • Ejecutables Python: {len(structure.get('python_executables', []))}")
        
        # Análisis de paquetes
        packages = report["package_analysis"]
        print(f"\n📦 Análisis de Paquetes:")
        print(f"   • Paquetes Instalados: {packages.get('total_packages', 0)}")
        print(f"   • Paquetes Desactualizados: {len(packages.get('outdated_packages', []))}")
        
        # Métricas de rendimiento
        performance = report["performance_metrics"]
        print(f"\n⚡ Métricas de Rendimiento:")
        print(f"   • Uso de Disco: {self._format_size(performance.get('disk_usage', 0))}")
        print(f"   • Puntuación de Eficiencia: {performance.get('efficiency_score', 0)}/100")
        print(f"   • Tiempo de Inicio Estimado: {performance.get('startup_time_estimate', 0)}s")
        
        # Análisis de seguridad
        security = report["security_analysis"]
        print(f"\n🔒 Análisis de Seguridad:")
        print(f"   • Puntuación de Seguridad: {security.get('security_score', 0)}/100")
        if security.get('potential_issues'):
            print(f"   • Problemas Potenciales: {len(security['potential_issues'])}")
        
        print()
    
    def _cleanup_old_backups(self, name: str):
        """Limpieza automática de backups antiguos."""
        try:
            retention_days = self.config.get("backup_retention_days", 30)
            cutoff_date = datetime.now().timestamp() - (retention_days * 24 * 3600)
            
            if name in self.metadata and "backups" in self.metadata[name]:
                backups = self.metadata[name]["backups"]
                backups_to_remove = []
                
                for backup in backups:
                    backup_date = datetime.fromisoformat(backup["timestamp"].replace("_", "T"))
                    if backup_date.timestamp() < cutoff_date:
                        backup_file = self.backup_dir / backup["file"]
                        if backup_file.exists():
                            backup_file.unlink()
                        backups_to_remove.append(backup)
                
                # Actualizar metadatos
                for backup in backups_to_remove:
                    backups.remove(backup)
                
                if backups_to_remove:
                    self._save_metadata()
                    print(f"🧹 Eliminados {len(backups_to_remove)} backups antiguos")
        
        except Exception as e:
            print(f"⚠️ Error en limpieza de backups: {str(e)}")
    
    def _calculate_directory_size(self, path: Path) -> int:
        """Cálculo recursivo del tamaño de directorio."""
        total_size = 0
        try:
            for root, dirs, files in os.walk(path):
                for file in files:
                    file_path = Path(root) / file
                    try:
                        total_size += file_path.stat().st_size
                    except (OSError, FileNotFoundError):
                        continue
        except Exception:
            pass
        return total_size
    
    def _format_size(self, size_bytes: int) -> str:
        """Formateo legible de tamaños de archivo."""
        if size_bytes == 0:
            return "0 B"
        
        size_names = ["B", "KB", "MB", "GB", "TB"]
        import math
        i = int(math.floor(math.log(size_bytes, 1024)))
        p = math.pow(1024, i)
        s = round(size_bytes / p, 2)
        return f"{s} {size_names[i]}"


class VEnvMasterCLI:
    """
    Interfaz de línea de comandos avanzada para VEnv-Master.
    Implementa patrones de interacción intuitivos y robustos.
    """
    
    def __init__(self):
        self.core = VEnvMasterCore()
        self.setup_argument_parser()
    
    def setup_argument_parser(self):
        """Configuración del parser de argumentos."""
        self.parser = argparse.ArgumentParser(
            description="VEnv-Master: Sistema Avanzado de Gestión de Entornos Virtuales",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Ejemplos de uso:
  %(prog)s create myproject --python 3.11
  %(prog)s list --detailed
  %(prog)s backup myproject
  %(prog)s audit myproject
  %(prog)s diagnose myproject
            """
        )
        
        subparsers = self.parser.add_subparsers(dest="command", help="Comandos disponibles")
        
        # Comando CREATE
        create_parser = subparsers.add_parser("create", help="Crear entorno virtual")
        create_parser.add_argument("name", help="Nombre del entorno")
        create_parser.add_argument("--manager", choices=["venv", "virtualenv", "conda"], 
                                 default="venv", help="Gestor de entornos")
        create_parser.add_argument("--python", help="Versión de Python")
        
        # Comando DESTROY
        destroy_parser = subparsers.add_parser("destroy", help="Eliminar entorno virtual")
        destroy_parser.add_argument("name", help="Nombre del entorno")
        destroy_parser.add_argument("--no-backup", action="store_true", 
                                  help="No crear backup antes de eliminar")
        
        # Comando USE (ACTIVATE)
        use_parser = subparsers.add_parser("use", help="Activar entorno virtual")
        use_parser.add_argument("name", help="Nombre del entorno")
        
        # Comando LIST
        list_parser = subparsers.add_parser("list", help="Listar entornos virtuales")
        list_parser.add_argument("--detailed", action="store_true", 
                               help="Mostrar información detallada")
        
        # Comando BACKUP
        backup_parser = subparsers.add_parser("backup", help="Crear backup del entorno")
        backup_parser.add_argument("name", help="Nombre del entorno")
        
        # Comando RESTORE
        restore_parser = subparsers.add_parser("restore", help="Restaurar entorno desde backup")
        restore_parser.add_argument("name", help="Nombre del entorno")
        restore_parser.add_argument("--timestamp", help="Timestamp específico del backup")
        
        # Comando AUDIT
        audit_parser = subparsers.add_parser("audit", help="Auditar entorno virtual")
        audit_parser.add_argument("name", help="Nombre del entorno")
        
        # Comando DIAGNOSE
        diagnose_parser = subparsers.add_parser("diagnose", help="Diagnosticar entorno virtual")
        diagnose_parser.add_argument("name", help="Nombre del entorno")
        
        # Comando CONFIG
        config_parser = subparsers.add_parser("config", help="Configurar VEnv-Master")
        config_parser.add_argument("--show", action="store_true", help="Mostrar configuración")
        config_parser.add_argument("--set", nargs=2, metavar=("KEY", "VALUE"), 
                                 help="Establecer valor de configuración")
    
    def run(self):
        """Ejecución principal de la CLI."""
        try:
            args = self.parser.parse_args()
            
            if not args.command:
                self.parser.print_help()
                return
            
            # Dispatch de comandos
            if args.command == "create":
                success = self.core.create_environment(
                    args.name, 
                    args.manager, 
                    args.python
                )
                sys.exit(0 if success else 1)
            
            elif args.command == "destroy":
                backup = not args.no_backup
                success = self.core.destroy_environment(args.name, backup)
                sys.exit(0 if success else 1)
            
            elif args.command == "use":
                success = self.core.activate_environment(args.name)
                sys.exit(0 if success else 1)
            
            elif args.command == "list":
                self.core.list_environments(args.detailed)
            
            elif args.command == "backup":
                success = self.core.backup_environment(args.name)
                sys.exit(0 if success else 1)
            
            elif args.command == "restore":
                success = self.core.restore_environment(args.name, args.timestamp)
                sys.exit(0 if success else 1)
            
            elif args.command == "audit":
                report = self.core.audit_environment(args.name)
                sys.exit(0 if report else 1)
            
            elif args.command == "diagnose":
                report = self.core.diagnose_environment(args.name)
                sys.exit(0 if report else 1)
            
            elif args.command == "config":
                self.handle_config_command(args)
            
        except KeyboardInterrupt:
            print("\n⚠️ Operación cancelada por el usuario")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error inesperado: {str(e)}")
            sys.exit(1)
    
    def handle_config_command(self, args):
        """Manejo del comando de configuración."""
        if args.show:
            print("⚙️ Configuración actual:")
            print("=" * 30)
            for key, value in self.core.config.items():
                print(f"{key}: {value}")
        
        elif args.set:
            key, value = args.set
            try:
                # Conversión automática de tipos
                if value.lower() in ["true", "false"]:
                    value = value.lower() == "true"
                elif value.isdigit():
                    value = int(value)
                elif "." in value and value.replace(".", "").isdigit():
                    value = float(value)
                
                self.core.config[key] = value
                
                # Guardar configuración
                with open(self.core.config_file, 'w') as f:
                    json.dump(self.core.config, f, indent=2)
                
                print(f"✅ Configuración actualizada: {key} = {value}")
                
            except Exception as e:
                print(f"❌ Error actualizando configuración: {str(e)}")
        else:
            print("❌ Debe especificar --show o --set")


def main():
    """Punto de entrada principal de VEnv-Master."""
    try:
        # Banner del sistema
        print("🐍 VEnv-Master v2.0 - Sistema Avanzado de Gestión de Entornos Virtuales")
        print("=" * 70)
        
        cli = VEnvMasterCLI()
        cli.run()
        
    except ImportError as e:
        print(f"❌ Error de dependencias: {str(e)}")
        print("💡 Asegúrese de tener Python 3.8+ instalado")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error crítico del sistema: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
CYBERPUNK SECURITY PROTOCOL v2.0 - SYSTEM INITIALIZER
Advanced Neural Network Password Analysis System
"""

import os
import sys
import subprocess
import time

def print_cyberpunk_banner():
    """Display the cyberpunk system banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║    🔮 CYBERPUNK SECURITY PROTOCOL v2.0 🔮                  ║
    ║                                                              ║
    ║    NEURAL NETWORK PASSWORD ANALYSIS SYSTEM                  ║
    ║                                                              ║
    ║    ═══════════════════════════════════════════════════════   ║
    ║                                                              ║
    ║    🧠 Neural Network: INITIALIZING...                       ║
    ║    🔐 Quantum Encryption: LOADING...                        ║
    ║    🌧️  Matrix Rain: ACTIVATING...                          ║
    ║    🎨 Cyberpunk UI: RENDERING...                            ║
    ║    🔊 Audio System: CALIBRATING...                          ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def check_dependencies():
    """Check if all required dependencies are installed"""
    print("🔍 CHECKING SYSTEM DEPENDENCIES...")
    
    required_packages = [
        'flask',
        'pycryptodome',
        'werkzeug'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
            print(f"✅ {package.upper()}: INSTALLED")
        except ImportError:
            print(f"❌ {package.upper()}: MISSING")
            missing_packages.append(package)
    
    if missing_packages:
        print(f"\n⚠️  MISSING DEPENDENCIES: {', '.join(missing_packages)}")
        print("🔧 INSTALLING MISSING PACKAGES...")
        
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'])
            print("✅ DEPENDENCIES INSTALLED SUCCESSFULLY")
        except subprocess.CalledProcessError:
            print("❌ FAILED TO INSTALL DEPENDENCIES")
            print("🔧 Please run: pip install -r requirements.txt")
            return False
    
    return True

def initialize_system():
    """Initialize the cyberpunk security system"""
    print("\n🚀 INITIALIZING CYBERPUNK SECURITY PROTOCOL...")
    
    # Check if backend.py exists
    if not os.path.exists('backend.py'):
        print("❌ ERROR: backend.py not found!")
        return False
    
    # Check if index.html exists
    if not os.path.exists('index.html'):
        print("❌ ERROR: index.html not found!")
        return False
    
    print("✅ SYSTEM FILES: VERIFIED")
    print("✅ NEURAL NETWORK: READY")
    print("✅ QUANTUM ENCRYPTION: ACTIVE")
    print("✅ SECURITY MATRIX: ONLINE")
    
    return True

def start_server():
    """Start the Flask development server"""
    print("\n🌐 STARTING CYBERPUNK WEB INTERFACE...")
    print("🔗 ACCESS URL: http://localhost:5000")
    print("🔗 SYSTEM STATUS: http://localhost:5000/system_status")
    print("\n⚠️  PRESS CTRL+C TO SHUTDOWN SYSTEM")
    print("=" * 60)
    
    try:
        # Import and run the Flask app
        from backend import app
        app.run(debug=True, host='0.0.0.0', port=5000)
    except KeyboardInterrupt:
        print("\n\n🛑 CYBERPUNK SECURITY PROTOCOL SHUTDOWN INITIATED...")
        print("🔒 NEURAL NETWORK: OFFLINE")
        print("🔐 QUANTUM ENCRYPTION: DISABLED")
        print("🌧️  MATRIX RAIN: STOPPED")
        print("✅ SYSTEM SHUTDOWN COMPLETE")
    except Exception as e:
        print(f"\n❌ SYSTEM ERROR: {e}")
        print("🔧 Please check your Python installation and dependencies")

def main():
    """Main system initialization function"""
    print_cyberpunk_banner()
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Initialize system
    if not initialize_system():
        sys.exit(1)
    
    # Start the server
    start_server()

if __name__ == "__main__":
    main()

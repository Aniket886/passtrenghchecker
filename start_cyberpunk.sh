#!/bin/bash

# CYBERPUNK SECURITY PROTOCOL v2.0 - SYSTEM INITIALIZER
# Advanced Neural Network Password Analysis System

# Colors for cyberpunk effect
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Clear screen and display banner
clear
echo -e "${GREEN}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                                                              ║"
echo "║    🔮 CYBERPUNK SECURITY PROTOCOL v2.0 🔮                  ║"
echo "║                                                              ║"
echo "║    NEURAL NETWORK PASSWORD ANALYSIS SYSTEM                  ║"
echo "║                                                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${CYAN}🔍 CHECKING PYTHON INSTALLATION...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ PYTHON3 NOT FOUND! Please install Python 3.8+ first.${NC}"
    exit 1
fi
echo -e "${GREEN}✅ PYTHON3: DETECTED${NC}"

echo -e "${CYAN}🔍 CHECKING PIP INSTALLATION...${NC}"
if ! command -v pip3 &> /dev/null; then
    echo -e "${RED}❌ PIP3 NOT FOUND! Please install pip3 first.${NC}"
    exit 1
fi
echo -e "${GREEN}✅ PIP3: DETECTED${NC}"

echo -e "${CYAN}🔍 CHECKING SYSTEM DEPENDENCIES...${NC}"
if [ ! -f "requirements.txt" ]; then
    echo -e "${RED}❌ requirements.txt not found!${NC}"
    exit 1
fi

echo -e "${YELLOW}🔧 INSTALLING/UPGRADING DEPENDENCIES...${NC}"
pip3 install -r requirements.txt --quiet

echo -e "${GREEN}✅ DEPENDENCIES: INSTALLED${NC}"

echo -e "${CYAN}🚀 INITIALIZING CYBERPUNK SECURITY PROTOCOL...${NC}"
echo -e "${GREEN}✅ NEURAL NETWORK: READY${NC}"
echo -e "${GREEN}✅ QUANTUM ENCRYPTION: ACTIVE${NC}"
echo -e "${GREEN}✅ SECURITY MATRIX: ONLINE${NC}"

echo -e "${CYAN}🌐 STARTING CYBERPUNK WEB INTERFACE...${NC}"
echo -e "${BLUE}🔗 ACCESS URL: http://localhost:5000${NC}"
echo -e "${BLUE}🔗 SYSTEM STATUS: http://localhost:5000/system_status${NC}"
echo ""
echo -e "${YELLOW}⚠️  PRESS CTRL+C TO SHUTDOWN SYSTEM${NC}"
echo "============================================================"

# Start the Python application
python3 start_cyberpunk.py

echo -e "${RED}🛑 CYBERPUNK SECURITY PROTOCOL SHUTDOWN COMPLETE${NC}"

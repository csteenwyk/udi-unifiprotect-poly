#!/usr/bin/env bash
pip3 install -r requirements.txt --user 2>&1 | tee logs/install.log
chmod +x unifiprotect-poly.py

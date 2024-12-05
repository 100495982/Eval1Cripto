#!/bin/bash

# Must already have a virtual environment created (python3 -m venv venv)

source venv/bin/activate
pip install -r requirements.txt
python main.py

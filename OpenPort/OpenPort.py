import psutil
import csv
import logging
from datetime import datetime

# Set up logging
logging.basicConfig(filename='open_ports.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

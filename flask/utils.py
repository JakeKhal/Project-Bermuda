"""
File: utils.py
Purpose: This file contains utility functions used across the Project Bermuda application.
Creation Date: 2024-11-07
Authors: Stephen Swanson, Alexandr Iapara, Emily Clauson, Jake Khal

The utility functions in this file assist with process management and file descriptor checks.

Modifications:
- 2024-11-07: Added function to check if a file descriptor is open.
"""

import os

# Function to check if a process with a given PID exists
# https://stackoverflow.com/questions/568271/how-to-check-if-there-exists-a-process-with-a-given-pid-in-python
def check_pid(pid):
    """
    Check for the existence of a Unix process with the given PID.
    
    Args:
        pid (int): The process ID to check.
    
    Returns:
        bool: True if the process exists, False otherwise.
    """
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    else:
        return True

# Function to check if a file descriptor is open
def is_fd_open(fd):
    """
    Check if a file descriptor is open.
    
    Args:
        fd (int): The file descriptor to check.
    
    Returns:
        bool: True if the file descriptor is open, False if it is closed.
    
    Raises:
        OSError: If an error other than "Bad file descriptor" occurs.
    """
    try:
        os.fstat(fd)
        return True  # If no exception, fd is open
    except OSError as e:
        if e.errno == 9:  # Errno 9 is "Bad file descriptor"
            return False
        else:
            raise  # Re-raise if it's a different error
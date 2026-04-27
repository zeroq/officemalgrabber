# -*- coding: utf-8 -*-
# Error utility functions - compatible with Python 2 and 3
# For adding filename and line number context to error messages

import sys
import traceback

def print_error(msg, e):
    """Print error with filename and line number."""
    # Get the call stack
    tb = sys.exc_info()[2]
    if tb is not None:
        # Get the traceback
        stack = traceback.extract_tb(tb)
        if len(stack) >= 2:
            frame = stack[-2]
            print("ERROR in %s:%d - %s: %s" % (frame.filename, frame.lineno, msg, e))
        else:
            print("ERROR: %s: %s" % (msg, e))
    else:
        print("ERROR: %s: %s" % (msg, e))

def log_exception(msg, e, json_result=None, quiet=False):
    """Log exception to json or stdout."""
    if quiet:
        return
    
    tb = sys.exc_info()[2]
    filename = "unknown"
    lineno = 0
    
    if tb is not None:
        stack = traceback.extract_tb(tb)
        if len(stack) >= 2:
            frame = stack[-2]
            filename = frame.filename
            lineno = frame.lineno
    
    full_msg = "ERROR in %s:%d - %s: %s" % (filename, lineno, msg, e)
    
    if json_result is not None:
        json_result['debug'].append(full_msg)
    else:
        print(full_msg)
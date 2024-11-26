import os

# https://stackoverflow.com/questions/568271/how-to-check-if-there-exists-a-process-with-a-given-pid-in-python
def check_pid(pid):        
    """ Check For the existence of a unix pid. """
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    else:
        return True

def is_fd_open(fd):
    try:
        os.fstat(fd)
        return True  # If no exception, fd is open
    except OSError as e:
        if e.errno == 9:  # Errno 9 is "Bad file descriptor"
            return False
        else:
            raise  # Re-raise if it's a different error
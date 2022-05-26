#!/usr/bin/env python
import sys
from src.bootstrap import tf

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("./make.py [FILENAME]")
        exit(1)
    tf.main(["src/bootstrap/tf.py", "-c", sys.argv[1]])

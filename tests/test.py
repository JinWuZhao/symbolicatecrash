import sys
sys.path.append('..')
from symbolicate import *

__author__ = 'jinzhao'

print(symbolicate_crash('/Users/jinzhao/Desktop/log.crash', lambda a, b, c, d, e: '/Users/jinzhao/Desktop/dSYMs/YouDu.app.dSYM/Contents/Resources/DWARF/YouDu', '/Users/jinzhao/Desktop/symbol_log.crash'))

import sys
import logging

__author__ = 'jinzhao'

#_loglevel_ = logging.INFO
#_stream_ = sys.stdout
_loglevel_ = logging.DEBUG
_stream_ = sys.stderr

logging.basicConfig(level=_loglevel_,
                    format='%(asctime)s %(pathname)s %(filename)s %(lineno)d %(funcName)s [%(levelname)s]:\n %(message)s',
                    stream=_stream_,
                    datefmt='%a, %d %b %Y %H:%M:%S')
logi = logging.info
loge = logging.error
logd = logging.debug

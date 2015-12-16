from logutils import *
import re
from subprocess import getstatusoutput

__author__ = 'jinzhao'


def set_app_dsym_finder(finder_func):
    """
    设置查询app可执行程序的符号文件的方法
    :param finder_func:处理函数，定义为:(name:String, identifier:String, version:String, codetype:String) -> (path)
    :return
    """
    pass

def symbolicate_crash(crash_log):
    """
    符号化crash日志
    :param crash_log:crash日志文件路径
    :return
    """
    pass


def _match_crash_header_re():
    """
    匹配Incident Identifier: xxxxxx-xxxx-xxxx-xxxx-xxxxxx等文字
    """
    return '^Incident\sIdentifier:\s*[A-F0-9\-]+\s*$'

def _match_product_name_re():
    """
    匹配Process: xxx [xxx]等文字
    """
    return '^Process:\s*([\S.]+)\s\[\d+\]\s*$'

def _match_identifier_re():
    """
    匹配Identifier: xxx.xxx.xxx等文字
    """
    return '^Identifier:\s*([a-z0-9_\-\.]+)\s*$'

def _match_version_re():
    """
    匹配应用版本号
    """
    return '^Version:\s*([\d\.]+)\s*$'

def _match_code_type_re():
    """
    匹配codetype
    """
    return '^Code\sType:\s*([a-zA-Z0-9\-]+)\s*$'

def _match_os_version_re():
    """
    匹配系统版本
    """
    return '^OS\sVersion:\s*iPhone\sOS\s(.+)\s*$'

def _match_stack_item_re():
    """
    匹配崩溃栈信息
    """
    return '^\d+\s+([a-zA-Z0-9\-_\+\.]+)\s+(0x[a-f0-9]+)\s(0x[a-f0-9]+)\s\+\s\d+\s*$'

def _sub_stack_item_symbol_re():
    """
    匹配崩溃栈中load_address以后的部分用于替换为符号部分
    """
    return '0x[a-f0-9]+\s\+\s[\d]+'

def _match_image_item_re():
    """
    匹配image信息
    """
    return '^\s*(0x[a-f0-9]+)\s\-\s+0x[a-f0-9]+\s+[^\+]?([a-zA-Z0-9\-_\+\.]+)\s+([a-z0-9]+)\s+<([a-f0-9]+)>\s([\S.]+)\s*$'

def _match_stack_header_re():
    """
    匹配崩溃栈信息头
    """
    return '^Last\sException\sBacktrace:\s*$|^Thread\s0\sCrashed:\s*$|^Thread\s0:\s*$'

def _match_image_header_re():
    """
    匹配image信息头
    """
    return '^Binary\sImages:\s*$'


class _CrashInfo(object):
    """
    crash数据结构
    """
    @property
    def product_name(self):
        if self.product_name is None:
            self.product_name = ''
        return self.product_name

    @property
    def identifier(self):
        if self.identifier is None:
            self.identifier = ''
        return self.identifier

    @property
    def version(self):
        if self.version is None:
            self.version = ''
        return self.version

    @property
    def code_type(self):
        if self.code_type is None:
            self.code_type = ''
        return self.code_type

    @property
    def os_version(self):
        if self.os_version is None:
            self.os_version = ''
        return self.os_version

    @property
    def function_stacks(self):
        if self.function_stacks is None:
            self.function_stacks = list()
        return self.function_stacks

    @property
    def binary_images(self):
        if self.binary_images is None:
            self.binary_images = dict()
        return self.binary_images


class _StackItemInfo(object):
    """
    栈信息结构
    """
    @property
    def line_num(self):
        if self.line_num is None:
            self.line_num = -1
        return self.line_num

    @property
    def name(self):
        if self.name is None:
            self.name = ''
        return self.name

    @property
    def invoke_address(self):
        if self.invoke_address is None:
            self.invoke_address = ''
        return self.invoke_address

    @property
    def load_address(self):
        if self.load_address is None:
            self.load_address = ''
        return self.load_address

    @property
    def invoke_symbol(self):
        if self.invoke_symbol is None:
            self.invoke_symbol = ''
        return self.invoke_symbol


class _ImageItemInfo(object):
    """
    Image信息结构
    """

    @property
    def load_address(self):
        if self.load_address is None:
            self.load_address = ''
        return self.load_address

    @property
    def name(self):
        if self.name is None:
            self.name = ''
        return self.name

    @property
    def code_type(self):
        if self.code_type is None:
            self.code_type = ''
        return self.code_type

    @property
    def uuid(self):
        if self.uuid is None:
            self.uuid = ''
        return self.uuid

    @property
    def symbol_file(self):
        if self.symbol_file is None:
            self.symbol_file = ''
        return self.symbol_file


def _read_log(path):
    """
    :param path: log file path
    :return status:Bool, lines:List
    """

    lines = list()
    try:
        with open(path, 'r') as file:
            logi('open file {log_path} for reading'.format(log_path=path))
            lines = file.readlines()
    except Exception as e:
        loge(e)
        return (False, list(), list())
    return (True, lines)

def _write_log(path, lines):
    """
    :param path: log file path
    :param lines: content
    :return status:Bool
    """
    try:
        with open(path, 'w') as file:
            logi('open file {log_path} for writting'.format(log_path=path))
            file.writelines(lines)
    except Exception as e:
        loge(e)
        return False
    return True

def _parse_content(lines):
    """
    :param lines: content
    :return crash_list: list of CrashInfo
    """
    header_part_complete = False
    stack_info_complete = False
    image_info_complete = False

    crash_list = list()
    re_obj = None
    crash_obj = None

    for line in lines:
        if header_part_complete is False:
            crash_obj, header_part_complete = _parse_crash_info(line, crash_obj)
        elif stack_info_complete is False:
            crash_obj, re_obj, stack_info_complete = _parse_stack_info(line, re_obj, crash_obj)
        elif image_info_complete is False:
            crash_obj, re_obj, image_info_complete = _parse_image_info(line, re_obj, crash_obj)
        else:
            crash_list.append(crash_obj)
            header_part_complete = False
            stack_info_complete = False
            image_info_complete = False
    return crash_list

def _parse_crash_info(line, crash_obj):
    """
    :param line: line string
    :param crash_obj: CrashInfo object
    :return: crash_obj, complete:Bool
    """
    complete = False
    if crash_obj is None:
        if re.match(_match_crash_header_re(), line) is not None:
            crash_obj = _CrashInfo()
    elif len(crash_obj.product_name) == 0 :
        match_obj = re.match(_match_product_name_re(), line)
        if match_obj is not None:
            crash_obj.product_name =  match_obj.group(1)
    elif len(crash_obj.identifier) == 0:
        match_obj = re.match(_match_identifier_re(), line)
        if match_obj is not None:
            crash_obj.identifier = match_obj.group(1)
    elif len(crash_obj.version) == 0:
        match_obj = re.match(_match_version_re(), line)
        if match_obj is not None:
            crash_obj.version = match_obj.group(1)
    elif len(crash_obj.code_type) == 0:
        match_obj = re.match(_match_code_type_re(), line)
        if match_obj is not None:
            crash_obj.code_type = match_obj.group(1)
    elif len(crash_obj.os_version) == 0:
        match_obj = re.match(_match_os_version_re(), line)
        if match_obj is not None:
            crash_obj.os_version = match_obj.group(1)
            complete = True
    return (crash_obj, complete)

def _parse_stack_info(line, re_obj, crash_obj, line_num):
    """
    :param line: line string
    :param re_obj: re compiled object
    :param crash_obj: CrashInfo object
    :return: crash_obj, re_obj, complete:Bool
    """
    complete = False
    match_obj = re.match(_match_stack_item_re(), line)
    if match_obj is not None:
        stack_item =  _StackItemInfo()
        stack_item.name = match_obj.group(1)
        stack_item.invoke_address = match_obj(2)
        stack_item.load_address = match_obj(3)
        stack_item.line_num = line_num
        crash_obj.function_stacks.append(stack_item)
    elif re.match(_match_image_header_re(), line) is not None:
        complete = True
    return (crash_obj, re_obj, complete)

def _parse_image_info(line, re_obj, crash_obj):
    """
    :param line: line string
    :param re_obj: re compiled object
    :param crash_obj: CrashInfo object
    :return: crash_obj, re_obj, complete:Bool
    """
    complete = False
    match_obj = re.match(_match_image_item_re(), line)
    if match_obj is not None:
        image_item = _ImageItemInfo()
        image_item.name = match_obj.

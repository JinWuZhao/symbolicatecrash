from logutils import *
import re
from subprocess import getstatusoutput

__author__ = 'jinzhao'

def symbolicate_crash(crash_log, finder_func, output_path=None):
    """
    符号化crash日志
    :param crash_log:crash日志文件路径
    :param finder_func:查询app符号文件的处理函数，定义为:(name:string, identifier:string, version:string, codetype:string) -> (path)
    :param output_path:符号化之后的crash文件路径，默认为none，表示直接输出到stdin
    :return 是否成功
    """
    status, lines = _read_log(crash_log)
    if status is false:
        loge('cannot open log file "{log_file}"'.format(log_file=crash_log))
        return False
    crash_list = _parse_content(lines, finder_func)
    newlines = _compose_log(crash_list, lines)
    if output_path is None:
        print(newlines)
    else:
        if _write_log(output_path, newlines) is False:
            loge('cannot write into file "{log_file}"'.format(log_file=output_path))
            return False
    return True

def _match_crash_header_re():
    """
    匹配Incident Identifier: xxxxxx-xxxx-xxxx-xxxx-xxxxxx等文字
    """
    return r'^Incident\sIdentifier:\s*[A-F0-9\-]+\s*$'

def _match_product_name_re():
    """
    匹配Process: xxx [xxx]等文字
    """
    return r'^Process:\s*([\S.]+)\s\[\d+\]\s*$'

def _match_identifier_re():
    """
    匹配Identifier: xxx.xxx.xxx等文字
    """
    return r'^Identifier:\s*([a-z0-9_\-\.]+)\s*$'

def _match_version_re():
    """
    匹配应用版本号
    """
    return r'^Version:\s*([\d\.]+)\s*$'

def _match_code_type_re():
    """
    匹配codetype
    """
    return r'^Code\sType:\s*([a-zA-Z0-9\-]+)\s*$'

def _match_os_version_re():
    """
    匹配系统版本
    """
    return r'^OS\sVersion:\s*iPhone\sOS\s(.+)\s*$'

def _match_stack_item_re():
    """
    匹配崩溃栈信息
    """
    return r'^\d+\s+([a-zA-Z0-9\-_\+\.]+)\s+(0x[a-f0-9]+)\s(0x[a-f0-9]+)\s\+\s\d+\s*$'

def _sub_stack_item_symbol_re():
    """
    匹配崩溃栈中load_address以后的部分用于替换为符号部分
    """
    return r'0x[a-f0-9]+\s\+\s[\d]+'

def _match_image_item_re():
    """
    匹配image信息
    """
    return r'^\s*(0x[a-f0-9]+)\s\-\s+0x[a-f0-9]+\s+[^\+]?([a-zA-Z0-9\-_\+\.]+)\s+([a-z0-9]+)\s+<([a-f0-9]+)>\s([\S.]+)\s*$'

def _match_stack_header_re():
    """
    匹配崩溃栈信息头
    """
    return r'^Last\sException\sBacktrace:\s*$|^Thread\s0\sCrashed:\s*$|^Thread\s0:\s*$'

def _match_image_header_re():
    """
    匹配image信息头
    """
    return r'^Binary\sImages:\s*$'

def _sub_proccess_file_path_re():
    """
    处理文件路径中shell不支持的空白字符和括号字符，添加转义
    """
    return r'([\\]?[\s\(\)])'

def _os_symbol_file_path_prefix():
    """
    iOS系统相关符号文件路径前缀
    """
    return '~/Library/Developer/Xcode/iOS DeviceSupport'

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

def _parse_content(lines, finder_func):
    """
    :param lines: content
    :param finder_func: (name:String, identifier:String, version:String, codetype:String) -> (path)
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
            crash_obj, re_obj, stack_info_complete = _parse_stack_info(line, re_obj, crash_obj, crash_list.index(line))
        elif image_info_complete is False:
            crash_obj, re_obj, image_info_complete = _parse_image_info(line, re_obj, crash_obj)
        else:
            crash_obj.binary_images[crash_obj.product_name].symbol_file = finder_func(crash_obj.product_name, crash_obj.identifier, crash_obj.version, crash_obj.code_type)
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
    if re_obj is None:
        re_obj = re.compile(_match_stack_item_re())
    complete = False
    match_obj = re_obj.match(line)
    if match_obj is not None:
        stack_item =  _StackItemInfo()
        stack_item.name = match_obj.group(1)
        stack_item.invoke_address = match_obj(2)
        stack_item.load_address = match_obj(3)
        stack_item.line_num = line_num
        crash_obj.function_stacks.append(stack_item)
    elif re.match(_match_image_header_re(), line) is not None:
        complete = True
        re_obj = None
    return (crash_obj, re_obj, complete)

def _parse_image_info(line, re_obj, crash_obj):
    """
    :param line: line string
    :param re_obj: re compiled object
    :param crash_obj: CrashInfo object
    :return: crash_obj, re_obj, complete:Bool
    """
    if re_obj is None:
        re_obj = re.compile(_match_image_item_re())
    complete = False
    match_obj = re_obj.match(line)
    if match_obj is not None:
        image_item = _ImageItemInfo()
        image_item.load_address = match_obj.group(1)
        image_item.name = match_obj.group(2)
        image_item.code_type = match_obj.group(3)
        image_item.uuid = match_obj.group(4)
        image_item.symbol_file = '{prefix}/{os_version}/{symbol_file}'\
                  ''.format(prefix=_os_symbol_file_path_prefix(),
                            os_version=crash_obj.os_version,
                            symbol_file=match_obj.group(5))
        crash_obj.binary_images[image_item.name] = image_item
    elif len(crash_obj.binary_images.items) > 0:
        complete = True
        re_obj = None
    return (crash_obj, re_obj, complete)

def _symbolicate_stack_items(crash_obj):
    """
    :param crash_obj: CrashInfo object
    :return: crash_obj
    """
    re_obj = re.compile(_sub_proccess_file_path_re())
    def proccess_path(match_obj):
        matched_str = match_obj.group(1)
        if len(matched_str) > 0 and matched_str[0] != '\\':
            return '\\'+matched_str
        return matched_str
    for stack_item in crash_obj.function_stacks:
        image_item = crash_obj.binary_images[stack_item.name]
        symbol_file_path = re_obj.sub(proccess_path, image_item.symbol_file)
        status, output = getstatusoutput('dwarfdump --uuid {symbol_file}'.format(symbol_file=symbol_file_path))
        if status == 0 and output == image_item.uuid:
            status, output = getstatusoutput('atos -arch {code_type} -o {symbol_file} -l {load_address} {invoke_address}'.format(code_type=image_item.code_type, symbol_file=symbol_file_path, load_address=stack_item.load_address, invoke_address=stack_item.invoke_address))
            if status == 0:
                stack_item.invoke_symbol = output
            else:
                loge(output)
        else:
            loge('warnning! symbol file "{symbol_file}": uuid is not matched ')

    return crash_obj

def _compose_log(crash_list, lines):
    """
    :param crash_list: CrashInfo list
    :param lines: origin log content
    :return: new log content
    """
    re_obj = re.compile(_sub_stack_item_symbol_re())
    for crash_obj in crash_list:
        for stack_item in crash_obj.function_stacks:
            lines[stack_item.line_num] = re_obj.sub(stack_item.invoke_symbol, lines[stack_item.line_num])
    return lines

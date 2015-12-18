import argparse
import symbolicate
import sys
import re

__author__ = 'jinzhao'

def _parse_params():
    """
    命令行参数解析
    :return: Parser对象
    """
    cmd_usage = """
    symbolicatedcrash [-v] {crash_log} {dsym_file} [-o {output_file}]

    options:
    -v run in verbose mode
    -o indicate ouput file
    """
    cmd_description = """
    author: jinzhao
    created at 12-17-2015.
    """
    parser = argparse.ArgumentParser(prog='Symbolicate crash log written by Python.', usage=cmd_usage, description=cmd_description)
    parser.add_argument('crash_log', nargs='?', action='store', type=str, help='crash log file, generally named xxx.crash')
    parser.add_argument('dsym_file', nargs='?', action='store', type=str, help='App symbolic file, generally named xxx.app.dSYM')
    group_param = parser.add_argument_group()
    group_param.add_argument('-v', '--verbose', action='store_true', dest='verbose_mode', help='run in verbose mode, with some debug infomation outputs')
    group_param.add_argument('-o', '--output', action='store', type=str, dest='output_file', help='indicate output file of symolicated crash log')
    return parser.parse_args()

def _main(args):
    """
    启动symbolicate程序
    :param args:解析后的命令行参数
    """
    if args.dsym_file is None:
        print('Error! You must indicate a dSYM file.')
        return 2
    re_obj = re.compile(r'^.*/(.+).app.dSYM$|^(.+).app.dSYM$')
    match_obj = re_obj.match(args.dsym_file)
    if match_obj is None:
        print('Error! The dSYM file is not valid.')
        return 2
    app_name = match_obj.group(1)
    dsym_file = args.dsym_file+'/Contents/Resources/DWARF/'+app_name
    if args.crash_log is None:
        print('Error! You must indicate a crash log file.')
        return 2
    crash_log = args.crash_log
    verbose_mode = args.verbose_mode
    output_file = args.output_file

    def finder_func(name, identifier, version, codetype, uuid):
        if verbose_mode is True:
            print('app name: {name}'.format(name=name))
            print('bundle identifier: {identifier}'.format(identifier=identifier))
            print('code type: {codetype}'.format(codetype=codetype))
            print('app uuid: {uuid}'.format(uuid=uuid))
            print('dsym file: {dsym_file}'.format(dsym_file=dsym_file))
        return dsym_file

    if symbolicate.symbolicate_crash(crash_log, finder_func, output_file, verbose_mode) is False:
        print('Error! task failed.')
        return 2
    return 0

sys.exit(_main(_parse_params()))

"""
Support for os, re and other modules which written for avoiding repetitive code.
"""
import re
import os
from modules import constants, run_command, file_functions, docker_commands

VM_CLASS_HIERARCHY = 'VM.class_hierarchy'
GC_CLASS_HISTOGRAM = 'GC.class_histogram'
HELP = 'help'
JDK_MINIMUM_VERSION = '10.0.0'


def get_java_version(debug, container_name):
    """This function returns the java version."""
    java_version_command = 'java -version'
    pipe_version = run_command.command_output(java_version_command, debug, container_name)
    java_version = pipe_version.stdout
    if not java_version:
        java_version = pipe_version.stderr
    for line in java_version.split('\n'):
        if 'openjdk version' in line.lower():
            values = line.split('"')
            for value in values:
                if re.search(r'\d*\.\d*.\d*', value):
                    return value
    return ''


def build_jcmd_path(pid, debug, container_name):
    """"This function build the jcmd path."""
    jcmd_path = 'jcmd'
    jdk_version = get_java_version(debug, container_name)
    if jdk_version:
        if JDK_MINIMUM_VERSION < jdk_version:
            jcmd_path = get_jcmd(pid, debug, container_name)
    else:
        return constants.UNSUPPORTED
    return jcmd_path


def get_jcmd(pid, debug, container_name):
    """This function returns the full path of the jcmd application in a container."""
    merged_dir_path = docker_commands.get_merge_dir(debug, container_name)
    if merged_dir_path == constants.UNSUPPORTED:
        return constants.UNSUPPORTED
    proc_path = f'/proc/{pid}/exe'
    get_jcmd_path_command = f'sudo ls -l {proc_path}'
    pipe_get_jcmd_path = run_command.command_output(get_jcmd_path_command, debug, container_name='')
    get_jcmd_path = pipe_get_jcmd_path.stdout
    if not get_jcmd_path:
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Unsupported "/proc/{pid}/exe" value'))
        return constants.UNSUPPORTED
    if '->' in get_jcmd_path:
        jcmd_path = merged_dir_path + get_jcmd_path.split(' ')[constants.END].rsplit('jdk', 1)[constants.START] + \
                    'jdk/bin'
        if os.path.isdir(jcmd_path):
            jcmd_path = jcmd_path + '/jcmd'
            if not file_functions.check_file_existence(jcmd_path, debug, container_name=''):
                jcmd_path = 'jcmd'
        else:
            jcmd_path = 'jcmd'
        return jcmd_path
    print(constants.FULL_EXPLANATION_MESSAGE.format(f'Unsupported "/proc/{pid}/exe" value'))
    return constants.UNSUPPORTED


def available_jcmd_utilities(jcmd_command, debug):
    """This checks the utility name in which it can take the classes from."""
    full_help_command = jcmd_command + HELP
    available_utilities = run_command.command_output(full_help_command, debug, container_name='')
    if available_utilities.stderr:
        print(constants.FULL_EXPLANATION_MESSAGE.format('The jcmd command is not available, try to download jdk tool'))
        return ''
    available_utilities_output = available_utilities.stdout
    if VM_CLASS_HIERARCHY in available_utilities_output:
        return VM_CLASS_HIERARCHY
    if GC_CLASS_HISTOGRAM in available_utilities_output:
        return GC_CLASS_HISTOGRAM
    print(constants.FULL_EXPLANATION_MESSAGE.format('The jcmd class utilities were not found'))
    return ''


def check_loaded_classes(pid, jcmd_command, classes, debug):
    """This function checks if the process is using the affected class."""
    pipe_jcmd = run_command.command_output(jcmd_command, debug, container_name='')
    jcmd = pipe_jcmd.stdout
    values = ''
    if not jcmd:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Unsupported class value'))
        return constants.UNSUPPORTED
    for affected_class in classes.keys():
        print(constants.FULL_QUESTION_MESSAGE.format(f'Does {pid} process load {affected_class}?'))
        if affected_class in jcmd:
            print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'The {pid} process loads the {affected_class} class'))
            if values:
                values += f', {classes[affected_class]}'
            else:
                values = classes[affected_class]
        else:
            print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'The {pid} process does not load the {affected_class}'
                                                            f' class'))
    return values

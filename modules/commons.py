"""
Support for os, re, semver, version from packaging and other modules which written for avoiding repetitive code.
"""
import os
import re
from packaging import version
from modules import run_command, constants, docker_commands, os_type, os_release, supported
VM_CLASS_HIERARCHY = 'VM.class_hierarchy'
GC_CLASS_HISTOGRAM = 'GC.class_histogram'
HELP = 'help'
JDK_MINIMUM_VERSION = '10.0.0'


def graph_start(cve, vol_graph):
    """Graphviz start function."""
    vol_graph.attr(label=f'{cve}\n\n', labelloc='t')
    vol_graph.attr('node', shape='box', style='filled', color='red')
    vol_graph.node(constants.GRAPH_VULNERABLE)
    vol_graph.attr('node', shape='box', style='filled', color='green')
    vol_graph.node(constants.GRAPH_NOT_VULNERABLE)
    vol_graph.attr('node', shape='box', color='lightgrey')


def graph_end(vol_graph):
    """Graphviz end function."""
    try:
        vol_graph.view()
    except ValueError:
        print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format(constants.NOT_INSTALLED_MESSAGE.format('Graphviz')))
        
        
def check_file_existence(file_path, debug, container_name):
    """This function checks if the file is exist in the system."""
    exist = False
    print(constants.FULL_QUESTION_MESSAGE.format(f'Is {file_path} file exists?'))
    if container_name:
        cat_file_command = f'cat {file_path}'
        pipe_cat_file = run_command.command_output(cat_file_command, debug, container_name)
        if pipe_cat_file.stdout:
            exist = True
    else:
        if os.path.isfile(file_path):
            exist = True
    if exist:
        print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('Yes'))
        print(constants.FULL_EXPLANATION_MESSAGE.format('The file exists in your system'))
    else:
        print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('No'))
        print(constants.FULL_EXPLANATION_MESSAGE.format('The file does not exist in your system'))
    return exist


def file_content(file_path, debug, container_name):
    """This function checks returns the file's content if exists."""
    content = ''
    if container_name:
        cat_file_command = f'cat {file_path}'
        pipe_cat_file = run_command.command_output(cat_file_command, debug, container_name)
        content = pipe_cat_file.stdout
        if content:
            content = content.split('\n')[:constants.END]
    else:
        if os.path.isfile(file_path):
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    content = []
                    for line in file.readlines():
                        content.append(line[:constants.END])
            except PermissionError:
                cat_file_command = f'sudo cat {file_path}'
                pipe_cat_file = run_command.command_output(cat_file_command, debug, container_name)
                content = pipe_cat_file.stdout
                if content:
                    content = content.split('\n')[:constants.END]
    return content


def re_start_of_version(full_version):
    """Returns the start of a version using regex."""
    start_of_version = re.search(r'\d*\.\d*', full_version)
    if start_of_version:
        return start_of_version.group()


def check_patched_version(version_type, checked_version, patched_versions):
    """This function checks if the version is affected according to patched versions which sorted in an ascending order
     list."""
    affected = False
    print(constants.FULL_QUESTION_MESSAGE.format(f'Is {version_type} version affected?'))
    if patched_versions[constants.START] in checked_version:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Your {version_type} version which is: {checked_version} has '
                                                        f'the patched version which is: '
                                                        f'{patched_versions[constants.START]}'))
    elif version.parse(checked_version) < version.parse(patched_versions[constants.START]):
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'The lowest patched version is: '
                                                        f'{patched_versions[constants.START]}\nYour {version_type}'
                                                        f' version which is: {checked_version}, is affected'))
        affected = True
    elif version.parse(checked_version) > version.parse(patched_versions[constants.END]) or \
            patched_versions[constants.END] in checked_version:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'The highest patched version is: '
                                                        f'{patched_versions[constants.END]}\nYour {version_type}'
                                                        f' version is: {checked_version}'))
    else:
        for patched_version in patched_versions[constants.FIRST:]:
            start_of_checked_version = re_start_of_version(checked_version)
            start_of_patched_version = re_start_of_version(patched_version)
            if version.parse(start_of_checked_version) < version.parse(start_of_patched_version):
                print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
                print(constants.FULL_EXPLANATION_MESSAGE.format(f'Your {version_type} version which is: '
                                                                f'{checked_version} is not patched'))
                affected = True
                break
            if patched_version.startswith(start_of_checked_version):
                if version.parse(checked_version) < version.parse(patched_version):
                    print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
                    print(constants.FULL_EXPLANATION_MESSAGE.format(f'The lowest patched version is: {patched_version}'
                                                                    f'\nYour {version_type} version is: '
                                                                    f'{checked_version}, is affected'))
                    affected = True
                    break
                if patched_version in checked_version:
                    print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
                    print(constants.FULL_EXPLANATION_MESSAGE.format(f'Your {version_type} version which is: '
                                                                    f'{checked_version} has the patched version which '
                                                                    f'is: {patched_versions}, is not affected'))
                else:
                    print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
                    print(constants.FULL_EXPLANATION_MESSAGE.format(f'The lowest patched version is: {patched_version}'
                                                                    f'\nYour {version_type} version which is: '
                                                                    f'{checked_version}, is not affected'))
                    break
    return affected


def compare_versions(fixed_version, host_version, package_name):
    """This function compares between the fixed version and the host's version."""
    affected = False
    print(constants.FULL_QUESTION_MESSAGE.format(f'Is {package_name} version affected?'))
    if version.parse(fixed_version) < version.parse(host_version):
        print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'The {package_name} patched versions is: {fixed_version}\nYour'
                                                        f' versions which is: {host_version}, is not affected'))
    elif version.parse(fixed_version) == version.parse(host_version):
        print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Your system is not affected because it has the {package_name}'
                                                        f' patched version which is: {fixed_version}'))
    else:
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'The {package_name} patched versions is: {fixed_version}\nYour'
                                                        f' versions which is: {host_version}, is affected'))
        affected = True
    return affected

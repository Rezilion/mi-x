"""
Support for os, re, semver, version from packaging and other modules which written for avoiding repetitive code.
"""
import os
import re
import semver
from packaging import version
from Modules import run_command, constants, docker_commands, os_type


def check_linux_and_affected_distribution(cve, debug, container_name):
    """This function checks if the machine is running on linux and if the os distribution is supported."""
    if os_type.is_linux(debug, container_name):
        if os_type.is_supported_distribution(debug, container_name):
            return True
        print(constants.FULL_NOT_DETERMINED_MESSAGE.format(cve))
        return False
    print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(cve))
    return False


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


def get_jcmd(pid, debug, container_name):
    """This function returns the full path of the jcmd application in a container."""
    merged_dir_path = docker_commands.get_merge_dir(container_name, debug)
    if merged_dir_path == constants.UNSUPPORTED:
        return constants.UNSUPPORTED
    proc_path = f'/proc/{pid}/exe'
    get_jcmd_path_command = f'sudo ls -l {proc_path}'
    pipe_get_jcmd_path = run_command.command_output(get_jcmd_path_command, debug, container_name=False)
    get_jcmd_path = pipe_get_jcmd_path.stdout
    if not get_jcmd_path:
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Unsupported "/proc/{pid}/exe" value'))
        return constants.UNSUPPORTED
    if '->' in get_jcmd_path:
        jcmd_path = get_jcmd_path.split(' ')[constants.END].split('/java')[constants.START] + '/jcmd'
        full_container_jcmd_path = merged_dir_path + jcmd_path
        return full_container_jcmd_path
    print(constants.FULL_EXPLANATION_MESSAGE.format(f'Unsupported "/proc/{pid}/exe" value'))
    return constants.UNSUPPORTED


def check_loaded_classes(pid, jcmd_command, classes, debug):
    """This function checks if the process is using the webmvc or webflux dependencies."""
    pipe_jcmd = run_command.command_output(jcmd_command, debug, container_name=False)
    jcmd = pipe_jcmd.stdout
    values = ''
    if not jcmd:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Unsupported "VM.class_hierarchy" value'))
        return constants.UNSUPPORTED
    for affected_class in classes.keys():
        print(constants.FULL_QUESTION_MESSAGE.format(f'Does {pid} process load {affected_class}?'))
        if affected_class in jcmd:
            print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'The {pid} process loads the {affected_class} class'))
            if values:
                values += f', {classes[affected_class]}'
            else:
                values = classes[affected_class]
        else:
            print(constants.FULL_POSITIVE_RESULT_MESSAGE)
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'The {pid} process does not load the {affected_class}'
                                                            f' class'))
    return values


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
    print(constants.FULL_QUESTION_MESSAGE.format(f'Is {file_path} file exists?'))
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
    if content:
        print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('Yes'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'The {file_path} exists in your system'))
    else:
        print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('No'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'The {file_path} does not exist in your system'))
    return content


def valid_kernel_version(full_version):
    """Returns the start of a valid kernel version using regex."""
    if full_version.endswith('\n'):
        full_version = full_version[:constants.END]
    kernel_version = re.search(r'\d*\.\d*.\d*-\d*.\d*', full_version).group()
    if kernel_version.endswith('-'):
        kernel_version = kernel_version[:-1]
    return kernel_version


def re_start_of_version(full_version):
    """Returns the start of a version using regex."""
    return re.search(r'\d*\.\d*', full_version).group()


def check_patched_version(version_type, checked_version, patched_versions):
    """This function checks if the version is affected according to patched versions which sorted in an ascending order
     list."""
    affected = False
    print(constants.FULL_QUESTION_MESSAGE.format(f'Is {version_type} version affected?'))
    if patched_versions[constants.START] in checked_version:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Your {version_type} version which is: {checked_version} has '
                                                        f'the patched version which is: '
                                                        f'{patched_versions[constants.START]}'))
    elif semver.compare(checked_version, patched_versions[constants.START]) == -1:
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'The lowest patched version is: '
                                                        f'{patched_versions[constants.START]}\nYour {version_type}'
                                                        f' version is: {checked_version}'))
        affected = True
    elif semver.compare(checked_version, patched_versions[constants.END]) == 1 \
            or patched_versions[constants.END] in checked_version:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'The highest patched version is: '
                                                        f'{patched_versions[constants.END]}\nYour {version_type}'
                                                        f' version is: {checked_version}'))
    else:
        for patched_version in patched_versions[constants.FIRST:]:
            start_of_checked_version = re_start_of_version(checked_version)
            start_of_patched_version = re_start_of_version(patched_version)
            if version.parse(start_of_checked_version) < version.parse(start_of_patched_version):
                print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
                print(constants.FULL_EXPLANATION_MESSAGE.format(f'Your {version_type} version which is: '
                                                                f'{checked_version} is not patched'))
                affected = True
                break
            if patched_version.startswith(start_of_checked_version):
                if semver.compare(checked_version, patched_version) == -1:
                    print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
                    affected = True
                    print(constants.FULL_EXPLANATION_MESSAGE.format(f'The lowest patched version is: {patched_version}'
                                                                    f'\nYour {version_type} version is: '
                                                                    f'{checked_version}'))
                    break
                if patched_version in checked_version:
                    print(constants.FULL_POSITIVE_RESULT_MESSAGE)
                    print(constants.FULL_EXPLANATION_MESSAGE.format(f'Your {version_type} version which is: '
                                                                    f'{checked_version} has the patched version which '
                                                                    f'is: {patched_versions}'))
                else:
                    print(constants.FULL_POSITIVE_RESULT_MESSAGE)
                    print(constants.FULL_EXPLANATION_MESSAGE.format(f'The lowest patched version is: {patched_version}'
                                                                    f'\nYour {version_type} version is: '
                                                                    f'{checked_version}'))
                    break
    return affected


def compare_versions(fixed_version, host_version, package_name):
    """This function compares between the fixed version and the host's version."""
    affected = False
    print(constants.FULL_QUESTION_MESSAGE.format(f'Is {package_name} version affected?'))
    if version.parse(fixed_version) < version.parse(host_version):
        print(constants.FULL_POSITIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Your {package_name} versions which is: {host_version}, is '
                                                        f'higher than the patched version which is: '
                                                        f'{fixed_version}'))
    elif version.parse(fixed_version) == version.parse(host_version):
        print(constants.FULL_POSITIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Your system has the {package_name} patched version which is: '
                                                        f'{fixed_version}'))
    else:
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Your {package_name} versions which is: {host_version}, is '
                                                        f'lower than the patched version which is: '
                                                        f'{fixed_version}'))
        affected = True
    return affected

from Modules import run_command, constants, docker_commands
from packaging import version
import os
import semver
import re


# This function returns the full path of the jcmd application in a container.
def get_jcmd(pid, debug, container_name):
    merged_dir_path = docker_commands.get_merge_dir(container_name, debug)
    if merged_dir_path == constants.UNSUPPORTED:
        return constants.UNSUPPORTED
    proc_path = f'/proc/{pid}/exe'
    get_jcmd_path_command = f'sudo ls -l {proc_path}'
    pipe_get_jcmd_path = run_command.command_output(get_jcmd_path_command, debug, container_name=False)
    get_jcmd_path = pipe_get_jcmd_path.stdout
    if get_jcmd_path:
        if get_jcmd_path.__contains__('->'):
            jcmd_path = get_jcmd_path.split(' ')[constants.END].split('/java')[constants.START] + '/jcmd'
            full_container_jcmd_path = merged_dir_path + jcmd_path
            return full_container_jcmd_path
        else:
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'Unsupported "/proc/{pid}/exe" value'))
            return constants.UNSUPPORTED
    else:
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Unsupported "/proc/{pid}/exe" value'))
        return constants.UNSUPPORTED


# This function checks if the process is using the webmvc or webflux dependencies.
def check_loaded_classes(pid, jcmd_command, classes, debug):
    pipe_jcmd = run_command.command_output(jcmd_command, debug, container_name=False)
    jcmd = pipe_jcmd.stdout
    values = ''
    if jcmd:
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
    else:
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Unsupported "VM.class_hierarchy" value'))
        return constants.UNSUPPORTED


# This function checks if the file is exist in the system.
def check_file_existence(file_path, debug, container_name):
    exist = False
    print(constants.FULL_QUESTION_MESSAGE.format(f'Is {file_path} file exists?'))
    if container_name:
        cat_file_command = f'cat {file_path}'
        pipe_cat_file = run_command.command_output(cat_file_command, debug, container_name)
        content = pipe_cat_file.stdout
        if content:
            print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('Yes'))
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'The file exists in your system'))
            exist = True
        else:
            print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('No'))
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'The file does not exist in your system'))
    else:
        if os.path.isfile(file_path):
            print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'The file exists in your system'))
            exist = True
        else:
            print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('No'))
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'The file does not exist in your system'))
    return exist


# This function checks returns the file's content if exists.
def file_content(file_path, debug, container_name):
    content = ''
    print(constants.FULL_QUESTION_MESSAGE.format(f'Is {file_path} file exists?'))
    if container_name:
        cat_file_command = f'cat {file_path}'
        pipe_cat_file = run_command.command_output(cat_file_command, debug, container_name)
        content = pipe_cat_file.stdout
        if content:
            print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('Yes'))
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'The file exists in your system'))
            content = content.split('\n')
        else:
            print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('No'))
            print(constants.FULL_EXPLANATION_MESSAGE.format('The file does not exist in your system'))
    else:
        if os.path.isfile(file_path):
            print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('Yes'))
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'The file exists in your system'))
            try:
                file = open(file_path, 'r')
                content = file.readlines()
            except PermissionError:
                cat_file_command = f'sudo cat {file_path}'
                pipe_cat_file = run_command.command_output(cat_file_command, debug, container_name)
                content = pipe_cat_file.stdout
                if content:
                    content = content.split('\n')
        else:
            print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('No'))
            print(constants.FULL_EXPLANATION_MESSAGE.format('The file does not exist in your system'))
    return content


# Returns the start of a valid kernel version using regex.
def valid_kernel_version(full_version):
    if full_version.endswith('\n'):
        full_version = full_version[:constants.END]
    return re.search('\d*\.\d*.\d*-\d*.\d*', full_version).group()


# Returns the start of a version using regex.
def re_start_of_version(full_version):
    return re.search('\d*\.\d*', full_version).group()


# This function checks if the version is affected according to patched versions which sorted in an ascending order list.
def check_patched_version(version_type, checked_version, patched_versions):
    affected = False
    print(constants.FULL_QUESTION_MESSAGE.format(f'Is {version_type} version affected?'))
    if checked_version.__contains__(patched_versions[constants.START]):
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
            or checked_version.__contains__(patched_versions[constants.END]):
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
            elif patched_version.startswith(start_of_checked_version):
                if semver.compare(checked_version, patched_version) == -1:
                    print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
                    affected = True
                    print(constants.FULL_EXPLANATION_MESSAGE.format(f'The lowest patched version is: {patched_version}'
                                                                    f'\nYour {version_type} version is: '
                                                                    f'{checked_version}'))
                    break
                elif checked_version.__contains__(patched_version):
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


# This function compares between the fixed version and the host's version.
def compare_versions(fixed_version, host_version, package_name):
    affected = False
    if version.parse(fixed_version) < version.parse(host_version):
        print(constants.FULL_POSITIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Your {package_name} versions which is: {host_version}, is '
                                                        f'bigger than the patched version which is: '
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


# Graphviz start function.
def graph_start(cve, vol_graph):
    vol_graph.attr(label=f'{cve}\n\n', labelloc='t')
    vol_graph.attr('node', shape='box', style='filled', color='red')
    vol_graph.node(constants.GRAPH_VULNERABLE)
    vol_graph.attr('node', shape='box', style='filled', color='green')
    vol_graph.node(constants.GRAPH_NOT_VULNERABLE)
    vol_graph.attr('node', shape='box', color='lightgrey')


# Graphviz end function.
def graph_end(vol_graph):
    try:
        vol_graph.view()
    except ValueError:
        print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format(constants.NOT_INSTALLED_MESSAGE.format('Graphviz')))
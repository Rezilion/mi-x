"""
Support for graphviz and other modules which written for avoiding repetitive code.
"""
import graphviz
from modules import run_command, get_pids, commons, constants, docker_commands

CVE_ID = 'CVE-2021-3711'
DESCRIPTION = f'''{CVE_ID}

CVSS Score: 9.8
NVD Link: https://nvd.nist.gov/vuln/detail/cve-2021-3711

Python 3.x through 3.9.1 has a buffer overflow in `PyCArg_repr` in `_ctypes/callproc.c`, because `sprintf` is used 
unsafely. The vulnerability can cause Remote Code Execution, but most likely lead to application Denial of Service or 
application crash.
'''
PATCHED_VERSIONS = ['3.6.13', '3.7.10', '3.8.8', '3.9.2']


def check_ctypes_loaded(pid, ctypes_file_name, debug):
    """This function checks if the ctypes file is loaded into the process memory or not."""
    pid_maps_path = f'/proc/{pid}/maps'
    pid_maps_file = commons.file_content(pid_maps_path, debug, container_name=False)
    if not pid_maps_file:
        return pid_maps_file
    print(constants.FULL_QUESTION_MESSAGE.format(f'Is the _ctypes module loaded to the {pid} process memory?'))
    for line in pid_maps_file:
        if ctypes_file_name in line:
            print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
            print(constants.FULL_EXPLANATION_MESSAGE.format('The _ctypes module is loaded'))
            return True
    print(constants.FULL_POSITIVE_RESULT_MESSAGE)
    print(constants.FULL_EXPLANATION_MESSAGE.format('The _ctypes module is not loaded'))
    return False


def find_ctypes_file_name(pid, debug, container_name):
    """This function finds the name of the _ctypes file."""
    pid_maps_path = f'sudo cat /proc/{pid}/maps'
    pipe_pid_maps_file = run_command.command_output(pid_maps_path, debug, container_name=False)
    pid_maps_file = pipe_pid_maps_file.stdout
    if not pid_maps_file:
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'The /proc/{pid}/maps file does not exist'))
        return constants.UNSUPPORTED
    modules_path = ''
    for line in pid_maps_file.split('\n'):
        if 'lib-dynload' in line:
            modules_path = line.split(' ')[constants.END].split('lib-dynload')[constants.START] + 'lib-dynload'
            break
    print(constants.FULL_QUESTION_MESSAGE.format('Does the _ctypes .so file exist?'))
    if not modules_path:
        print(constants.FULL_EXPLANATION_MESSAGE.format('There is no python modules path'))
        return constants.UNSUPPORTED
    if container_name:
        merge_dir = docker_commands.get_merge_dir(container_name, debug)
        modules_path = merge_dir + modules_path
    list_modules_command = f'sudo ls {modules_path}'
    pipe_list_modules = run_command.command_output(list_modules_command, debug, container_name=False)
    list_modules = pipe_list_modules.stdout
    if not list_modules:
        print(constants.FULL_EXPLANATION_MESSAGE.format('No modules in python lib-dynload'))
        return constants.UNSUPPORTED
    for module in list_modules.split('\n'):
        if module.startswith('_ctypes') and module.endswith('.so') and not 'test' in module:
            print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'The _ctypes .so file exists : {module}'))
            return module
    print(constants.FULL_POSITIVE_RESULT_MESSAGE)
    print(constants.FULL_EXPLANATION_MESSAGE.format('The _ctypes .so file does not exist'))
    return False


def get_python_version(pid, debug, container_name):
    """This function returns the python version of the process."""
    pid_maps_path = f'/proc/{pid}/maps'
    pid_maps_file = commons.file_content(pid_maps_path, debug, container_name=False)
    if not pid_maps_file:
        return pid_maps_file
    path_to_modules = ''
    for line in pid_maps_file:
        if 'lib-dynload' in line:
            path_to_modules = line
            break
    if not path_to_modules:
        return path_to_modules
    path_values = path_to_modules.split('/')
    python_executable = ''
    for value in path_values:
        if value.startswith('python') or value.startswith('Python'):
            python_executable = value
            break
    python_version_command = f'{python_executable} --version'
    pipe_python_version = run_command.command_output(python_version_command, debug, container_name)
    host_python_version = pipe_python_version.stdout
    if host_python_version:
        return host_python_version.split(' ')[constants.END][:constants.END]
    return constants.UNSUPPORTED


def validate_processes(pids, debug, container_name):
    """This function loops over all Python processes and checks if they are vulnerable."""
    for pid in pids:
        python_version = get_python_version(pid, debug, container_name)
        if python_version == constants.UNSUPPORTED:
            print(constants.FULL_PROCESS_NOT_DETERMINED_MESSAGE.format(CVE_ID, pid))
        elif python_version:
            if commons.check_patched_version('Python', python_version, PATCHED_VERSIONS):
                ctypes_file_name = find_ctypes_file_name(pid, debug, container_name)
                if ctypes_file_name == constants.UNSUPPORTED:
                    print(constants.FULL_PROCESS_NOT_DETERMINED_MESSAGE.format(CVE_ID, pid))
                elif ctypes_file_name:
                    if check_ctypes_loaded(pid, ctypes_file_name, debug):
                        print(constants.FULL_PROCESS_VULNERABLE_MESSAGE.format(pid, CVE_ID))
                    else:
                        print(constants.FULL_PROCESS_NOT_VULNERABLE_MESSAGE.format(pid, CVE_ID))
                else:
                    print(constants.FULL_PROCESS_NOT_VULNERABLE_MESSAGE.format(pid, CVE_ID))
            else:
                print(constants.FULL_PROCESS_NOT_VULNERABLE_MESSAGE.format(pid, CVE_ID))
        else:
            print(constants.FULL_PROCESS_NOT_VULNERABLE_MESSAGE.format(pid, CVE_ID))


def validate(debug, container_name):
    """This function validates if the host is vulnerable to CVE-2021-3177."""
    if commons.check_linux_and_affected_distribution(CVE_ID, debug, container_name):
        pids = get_pids.pids_consolidation('python', debug, container_name)
        if pids:
            validate_processes(pids, debug, container_name)
        else:
            print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))


def validation_flow_chart():
    """This function creates graph that shows the vulnerability validation process of CVE-2021-3177."""
    vol_graph = graphviz.Digraph('G', filename=CVE_ID)
    commons.graph_start(CVE_ID, vol_graph)
    vol_graph.edge('Is it Linux?', 'Are there running Python processes?', label='Yes')
    vol_graph.edge('Is it Linux?', 'Not Vulnerable', label='No')
    vol_graph.edge('Are there running Python processes?', 'Is python version affected?', label='Yes')
    vol_graph.edge('Are there running Python processes?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is python version affected?', 'Is ctypes module loaded into memory?', label='Yes')
    vol_graph.edge('Is python version affected?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is ctypes module loaded into memory?', 'Vulnerable', label='Yes')
    vol_graph.edge('Is ctypes module loaded into memory?', 'Not Vulnerable', label='No')
    commons.graph_end(vol_graph)


def main(describe, graph, debug, container_name):
    """This is the main function."""
    if describe:
        print(f'\n{DESCRIPTION}')
    validate(debug, container_name)
    if graph:
        validation_flow_chart()

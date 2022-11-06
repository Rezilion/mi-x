"""
Support for graphviz and other modules which written for avoiding repetitive code.
"""
import graphviz
from modules import constants, graph_functions, status, run_command, file_functions, process_functions, versions_function

VULNERABILITY = 'CVE-2021-3711'
DESCRIPTION = f'''{VULNERABILITY}

CVSS Score: 9.8
NVD Link: https://nvd.nist.gov/vuln/detail/cve-2021-3711

Python 3.x through 3.9.1 has a buffer overflow in `PyCArg_repr` in `_ctypes/callproc.c`, because `sprintf` is used 
unsafely. The vulnerability can cause Remote Code Execution, but most likely lead to application Denial of Service or 
application crash.

Related Links:
https://www.randori.com/blog/cve-2021-3177-vulnerability-analysis/
https://cybersophia.net/news/python-vulnerability-cve-2021-3177/
'''
PATCHED_VERSIONS = ['3.6.13', '3.7.10', '3.8.8', '3.9.2']
REMEDIATION = 'Upgrade the Python version to one of the following 3.6.13, 3.7.10, 3.8.8, 3.9.2 or higher.'
MITIGATION = ''


def check_ctypes_loaded(pid, ctypes_file_name, debug):
    """This function checks if the ctypes file is loaded into the process memory or not."""
    pid_maps_path = f'/proc/{pid}/maps'
    pid_maps_file = file_functions.file_content(pid_maps_path, debug, container_name='')
    if not pid_maps_file:
        return pid_maps_file
    print(constants.FULL_QUESTION_MESSAGE.format(f'Is the _ctypes module loaded to the {pid} process memory?'))
    for line in pid_maps_file:
        if ctypes_file_name in line:
            print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
            print(constants.FULL_EXPLANATION_MESSAGE.format('The _ctypes module is loaded'))
            return True
    print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
    print(constants.FULL_EXPLANATION_MESSAGE.format('The _ctypes module is not loaded'))
    return False


def find_ctypes_file_name(pid, debug, container_name):
    """This function finds the name of the _ctypes file."""
    so_path = process_functions.check_loaded_so_file_to_process(pid, 'lib-dynload', debug, container_name)
    print(constants.FULL_QUESTION_MESSAGE.format('Is the _ctypes .so file loaded to the process memory?'))
    if not so_path:
        print(constants.FULL_EXPLANATION_MESSAGE.format('There is no python modules path'))
        return constants.UNSUPPORTED
    so_path = so_path.split('lib-dynload')[constants.START] + 'lib-dynload'
    list_modules_command = f'sudo ls {so_path}'
    pipe_list_modules = run_command.command_output(list_modules_command, debug, container_name='')
    list_modules = pipe_list_modules.stdout
    if not list_modules:
        print(constants.FULL_EXPLANATION_MESSAGE.format('No modules in python lib-dynload'))
        return constants.UNSUPPORTED
    for module in list_modules.split('\n'):
        if module.startswith('_ctypes') and module.endswith('.so') and not 'test' in module:
            print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'The _ctypes .so file exists : {module}'))
            return module
    print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
    print(constants.FULL_EXPLANATION_MESSAGE.format('The _ctypes .so file does not exist'))
    return False


def get_python_version(pid, debug, container_name):
    """This function returns the python version of the process."""
    version_output = process_functions.process_executable_version(pid, debug, container_name)
    if version_output == constants.UNSUPPORTED:
        return constants.UNSUPPORTED
    python_version = version_output.split(' ')[constants.END]
    return python_version


def validate_processes(pids, debug, container_name):
    """This function loops over all Python processes and checks if they are vulnerable."""
    state = {}
    for pid in pids:
        python_version = get_python_version(pid, debug, container_name)
        if python_version == constants.UNSUPPORTED:
            state[pid] = status.process_not_determined(pid, VULNERABILITY)
        elif python_version:
            if versions_functions.check_patched_version('Python', python_version, PATCHED_VERSIONS):
                ctypes_file_name = find_ctypes_file_name(pid, debug, container_name)
                if ctypes_file_name == constants.UNSUPPORTED:
                    state[pid] = status.process_not_determined(pid, VULNERABILITY)
                elif ctypes_file_name:
                    if check_ctypes_loaded(pid, ctypes_file_name, debug):
                        state[pid] = status.process_vulnerable(pid, VULNERABILITY)
                        status.remediation_mitigation(REMEDIATION, MITIGATION)
                    else:
                        state[pid] = status.process_not_vulnerable(pid, VULNERABILITY)
                else:
                    state[pid] = status.process_not_vulnerable(pid, VULNERABILITY)
            else:
                state[pid] = status.process_not_vulnerable(pid, VULNERABILITY)
        else:
            state[pid] = status.process_not_vulnerable(pid, VULNERABILITY)
    return state


def validate(debug, container_name):
    """This function validates if the host is vulnerable to CVE-2021-3177."""
    state = {}
    pids = process_functions.pids_consolidation('python', debug, container_name)
    if pids:
        state[VULNERABILITY] = validate_processes(pids, debug, container_name)
    else:
        state[VULNERABILITY] = status.not_vulnerable(VULNERABILITY)
    return state


def validation_flow_chart():
    """This function creates graph that shows the vulnerability validation process of CVE-2021-3177."""
    vol_graph = graphviz.Digraph('G', filename=VULNERABILITY, format='png')
    graph_functions.graph_start(VULNERABILITY, vol_graph)
    vol_graph.edge('Is it Linux?', 'Are there running Python processes?', label='Yes')
    vol_graph.edge('Is it Linux?', 'Not Vulnerable', label='No')
    vol_graph.edge('Are there running Python processes?', 'Is python version affected?', label='Yes')
    vol_graph.edge('Are there running Python processes?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is python version affected?', 'Is ctypes module loaded into memory?', label='Yes')
    vol_graph.edge('Is python version affected?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is ctypes module loaded into memory?', 'Vulnerable', label='Yes')
    vol_graph.edge('Is ctypes module loaded into memory?', 'Not Vulnerable', label='No')
    graph_functions.graph_end(vol_graph)


def main(description, graph, debug, container_name):
    """This is the main function."""
    if description:
        print(f'\n{DESCRIPTION}')
    state = validate(debug, container_name)
    if graph:
        validation_flow_chart()
    return state

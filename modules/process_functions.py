"""
Support for re and modules written to avoid repetitive code.
"""
import re
from modules import constants, run_command, file_functions, docker_commands

SO = '.so'


def get_container_full_path(path, debug, container_name):
    """This function returns the full path of a file in a container."""
    merge_dir = docker_commands.get_merge_dir(debug, container_name)
    path = f'{merge_dir}{path}'
    return path


def get_loaded_so_files_of_a_process(pid, debug, container_name):
    """This function returns all so files within the running process."""
    pid_maps_path = f'/proc/{pid}/maps'
    pid_maps_content = file_functions.get_file_content(pid_maps_path, debug, container_name='')
    so_files = []
    if pid_maps_content:
        for line in pid_maps_content:
            if SO in line:
                so_path = line.split(' ')[constants.END]
                so_files.append(so_path)
                if container_name:
                    container_file_path = get_container_full_path(so_path, debug, container_name)
                    so_files.append(container_file_path)
    return so_files


def check_loaded_so_file_to_process(pid, so_file, debug, container_name):
    """This function returns the path of the loaded so file if loaded."""
    pid_maps_path = f'/proc/{pid}/maps'
    pid_maps_content = file_functions.get_file_content(pid_maps_path, debug, container_name='')
    so_path = ''
    for line in pid_maps_content:
        if so_file in line:
            so_path = line.split(' ')[constants.END]
            if container_name:
                merge_dir = docker_commands.get_merge_dir(debug, container_name)
                so_path = merge_dir + so_path
            return so_path
    return so_path


def find_relevant_pids(pids, container_pids_list, debug, container_name):
    """This function returns the container pids that are matched with the host pids."""
    relevant_pids = []
    for field in pids:
        host_pid = field.split(' ')[constants.START]
        container_pid = field.split(' ')[constants.END]
        if container_pid in container_pids_list:
            host_maps_file = f'/proc/{host_pid}/maps'
            container_maps_file = f'/proc/{container_pid}/maps'
            host_maps_content = file_functions.get_file_content(host_maps_file, debug, container_name='')
            container_maps_content = file_functions.get_file_content(container_maps_file, debug, container_name)
            if host_maps_content == container_maps_content:
                relevant_pids.append(host_pid)
    print(constants.FULL_QUESTION_MESSAGE.format(f'Is there a match between container pids to host pids?'))
    if relevant_pids:
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
        pids_string = ", ".join(relevant_pids)
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'The following pids: {pids_string} have a match with '
                                                        f'container pids'))
        return relevant_pids
    print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
    print(constants.FULL_EXPLANATION_MESSAGE.format(f'There is no match between host pids and container pids'))
    return relevant_pids


def find_pids_from_status_file(pids, debug, container_name):
    """This function return a list of the relevant pids."""
    relevant_pids = []
    for pid in pids:
        pid_status_path = f'/proc/{pid}/status'
        pid_status_content = file_functions.get_file_content(pid_status_path, debug, container_name='')
        if pid_status_content:
            for line in pid_status_content:
                if line.startswith('NSpid:'):
                    if container_name:
                        if len(line.split('\t')) == 3:
                            pids_info = pid + ' ' + line.split('\t')[constants.END].split('\n')[constants.START]
                            relevant_pids.append(pids_info)
                    else:
                        if len(line.split('\t')) == 2:
                            relevant_pids.append(pid)
                    break
    return relevant_pids


def list_of_running_processes(debug, container_name):
    """This function returns all running processes."""
    list_proc_command = 'ls /proc'
    list_proc_pipe = run_command.command_output(list_proc_command, debug, container_name)
    list_proc = list_proc_pipe.stdout
    pids = re.findall('\d*', list_proc)
    pids = list(set(pids))
    if '' in pids:
        pids.remove('')
    return pids


def running_processes(debug, container_name):
    """This function returns all the relevant running processes."""
    host_pids = list_of_running_processes(debug, container_name='')
    if container_name:
        pids = find_pids_from_status_file(host_pids, debug, container_name)
        container_pids = list_of_running_processes(debug, container_name)
        return find_relevant_pids(pids, container_pids, debug, container_name)
    return host_pids


def aggregate_pids_to_list(pids, other_pids):
    """This function aggregate the pids."""
    if not pids:
        pids = other_pids
    else:
        if other_pids:
            pids.append(other_pids)
    if pids:
        pids = list(set(pids))
    return pids


def check_another_format_of_process_type(process_type):
    """This function checks if there are running processes with capital letter of the process and without."""
    if process_type.islower():
        process_type = process_type[constants.START].upper() + process_type[constants.FIRST:]
    else:
        process_type = process_type.lower()
    return process_type


def check_running_processes_by_name(process_type, software, debug, container_name):
    """This function checks if there are running processes on the relevant software."""
    pids_command = f'pgrep {process_type}'
    pipe_pids = run_command.command_output(pids_command, debug, container_name)
    pids = pipe_pids.stdout
    print(constants.FULL_QUESTION_MESSAGE.format(f'Are there running {process_type} processes on the {software}?'))
    if not pids:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'There are no running {process_type} processes'))
        return []
    pids_list = pids.split('\n')[:constants.END]
    print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
    print(constants.FULL_EXPLANATION_MESSAGE.format(f'The following PIDs are running {process_type} processes: '
                                                    f'{pids_list}'))
    return pids_list


def get_pids_by_name(process_type, debug, container_name):
    """This function checks if there are running processes of the received process type."""
    software = 'host'
    pids_list = check_running_processes_by_name(process_type, software, debug, container_name='')
    if pids_list:
        relevant_pids = find_pids_from_status_file(pids_list, debug, container_name)
    else:
        return pids_list
    print(constants.FULL_QUESTION_MESSAGE.format(f'Are there relevant running {process_type} processes on the '
                                                 f'{software}?'))
    if relevant_pids:
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'The following PIDs are relevant running {process_type} '
                                                        f'processes: {relevant_pids}'))
        return relevant_pids
    print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
    print(constants.FULL_EXPLANATION_MESSAGE.format(f'There are no relevant running {process_type} processes'))
    return relevant_pids


def get_pids_by_name_container(process_type, debug, container_name):
    """This function extracts the container running processes of the received process type ids on the host."""
    software = 'container'
    container_pids_list = check_running_processes_by_name(process_type, software, debug, container_name)
    host_pid_and_container_pid = get_pids_by_name(process_type, debug, container_name)
    if host_pid_and_container_pid:
        host_pid_and_container_pid = list(set(host_pid_and_container_pid))
        return find_relevant_pids(host_pid_and_container_pid, container_pids_list, debug, container_name)
    else:
        return host_pid_and_container_pid


def pids_consolidation(process_type, debug, container_name):
    """This function returns the pids by calling the functions above."""
    if container_name:
        pids = get_pids_by_name_container(process_type, debug, container_name)
        process_type = check_another_format_of_process_type(process_type)
        other_pids = get_pids_by_name_container(process_type, debug, container_name)
        pids = aggregate_pids_to_list(pids, other_pids)
    else:
        pids = get_pids_by_name(process_type, debug, container_name)
        process_type = check_another_format_of_process_type(process_type)
        other_pids = get_pids_by_name(process_type, debug, container_name)
        pids = aggregate_pids_to_list(pids, other_pids)
    return pids


def read_output(command, pid, value, debug, container_name):
    """This function returns command results and prints an error if something is wrong."""
    pipe = run_command.command_output(command, debug, container_name)
    output = pipe.stdout[:constants.END]
    if not output:
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Error while reading the {pid} process executable {value}'))
    return output


def get_process_executable(pid, debug, container_name):
    """This function returns the process's executable."""
    executable_link_command = f'readlink -f /proc/{pid}/exe'
    pipe = run_command.command_output(executable_link_command, debug, container_name='')
    executable_link = pipe.stdout[:constants.END]
    if executable_link:
        if container_name:
            executable_link = get_container_full_path(executable_link, debug, container_name)
    return executable_link


def process_executable_version(pid, debug, container_name):
    """This function returns the process's executable version."""
    executable_link_command = f'readlink -f /proc/{pid}/exe'
    executable_link = read_output(executable_link_command, pid, 'file', debug, container_name='')
    if executable_link:
        if container_name:
            executable_link = get_container_full_path(executable_link, debug, container_name)
        executable_version_command = f'{executable_link} --version'
        version = read_output(executable_version_command, pid, 'version', debug, container_name)
        if version:
            return version
    return ''

"""
Support for modules which written for avoiding repetitive code.
"""
from modules import run_command, commons, constants


def get_pids_by_name(process_type, debug, container_name):
    """This function checks if there are Java running processes."""
    pids_command = f'pgrep {process_type}'
    pipe_pids = run_command.command_output(pids_command, debug, container_name='')
    pids = pipe_pids.stdout
    print(constants.FULL_QUESTION_MESSAGE.format(f'There are running {process_type} processes on the host?'))
    if not pids:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'There are no running {process_type} processes'))
        return []
    pids_list = pids.split('\n')[:constants.END]
    print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
    print(constants.FULL_EXPLANATION_MESSAGE.format(f'The following PIDs are running {process_type} processes: '
                                                    f'{pids_list}'))
    relevant_pids = []
    for pid in pids_list:
        pid_status_path = f'/proc/{pid}/status'
        pid_status_content = commons.file_content(pid_status_path, debug, container_name='')
        if not pid_status_content:
            return []
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
    print(constants.FULL_QUESTION_MESSAGE.format(f'There are relevant running {process_type} processes on the '
                                                 f'host?'))
    if relevant_pids:
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'The following PIDs are relevant running {process_type} '
                                                        f'processes: {relevant_pids}'))
        return relevant_pids
    print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
    print(constants.FULL_EXPLANATION_MESSAGE.format(f'There are no relevant running {process_type} processes'))
    return relevant_pids


def get_pids_by_name_container(process_type, debug, container_name):
    """This function extracts the container java processes ids on the host."""
    pgrep_command = f'pgrep {process_type}'
    pipe_pids_container = run_command.command_output(pgrep_command, debug, container_name)
    pids_container = pipe_pids_container.stdout
    print(constants.FULL_QUESTION_MESSAGE.format(f'There are running {process_type} processes on the {container_name} '
                                                 f'container?'))
    if not pids_container:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'There are no running {process_type} processes'))
        return []
    print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
    container_pids_list = pids_container.split('\n')[:constants.END]
    print(constants.FULL_EXPLANATION_MESSAGE.format(f'The following PIDs are running {process_type} processes on '
                                                    f'the container: {container_pids_list}'))
    host_pid_and_container_pid = get_pids_by_name(process_type, debug, container_name)
    if process_type.islower():
        process_type = process_type[constants.START].upper() + process_type[constants.FIRST:]
    else:
        process_type = process_type.lower()
    other_pids = get_pids_by_name(process_type, debug, container_name)
    if not host_pid_and_container_pid:
        host_pid_and_container_pid = other_pids
    else:
        if other_pids:
            host_pid_and_container_pid.append(other_pids)
    host_pid_and_container_pid = list(set(host_pid_and_container_pid))
    relevant_pids = []
    for field in host_pid_and_container_pid:
        host_pid = field.split(' ')[constants.START]
        container_pid = field.split(' ')[constants.END]
        if container_pid in container_pids_list:
            relevant_pids.append(host_pid)
    print(constants.FULL_QUESTION_MESSAGE.format('There is a match between container pids to host pids?'))
    if relevant_pids:
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'The following pids: {relevant_pids} have a match with '
                                                        f'container pids'))
        return relevant_pids
    print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
    print(constants.FULL_EXPLANATION_MESSAGE.format('There is no match between host pids and container pids'))
    return relevant_pids


def pids_consolidation(process_type, debug, container_name):
    """This function returns the pids by calling the functions above."""
    if container_name:
        pids = get_pids_by_name_container(process_type, debug, container_name)
        if process_type.islower():
            process_type = process_type[constants.START].upper() + process_type[constants.FIRST:]
        else:
            process_type = process_type.lower()
        other_pids = get_pids_by_name_container(process_type, debug, container_name)
        if not pids:
            pids = other_pids
        else:
            if other_pids:
                pids.append(other_pids)
        pids = list(set(pids))
    else:
        pids = get_pids_by_name(process_type, debug, container_name)
        if process_type.islower():
            process_type = process_type[constants.START].upper() + process_type[constants.FIRST:]
        else:
            process_type = process_type.lower()
        other_pids = get_pids_by_name(process_type, debug, container_name)
        if not pids:
            pids = other_pids
        else:
            if other_pids:
                pids.append(other_pids)
        pids = list(set(pids))
    return pids


def read_output(command, value, debug, container_name):
    """This function returns command results and prints an error if something is wrong."""
    pipe = run_command.command_output(command, debug, container_name)
    output = pipe.stdout[:constants.END]
    if not output:
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Error while reading the {pid} process executable {value}'))
        return constants.UNSUPPORTED
    return output
    

def process_executable_version(pid, debug, container_name):
    """This function returns the process's executable version."""
    executable_link_command = f'readlink -f /proc/{pid}/exe'
    executable_link = read_output(executable_link_command, 'file', debug, container_name)
    if not executable_link == constants.UNSUPPORTED:
        executable_version_command = f'{executable_link} --version'
        version = read_output(executable_version_command, 'version', debug, container_name)
        if not version == constants.UNSUPPORTED:
            return version
    return constants.UNSUPPORTED

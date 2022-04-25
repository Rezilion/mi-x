import Modules.constants as constants
import Modules.run_command as run_command
import Modules.commons as commons


# This function checks if there are Java running processes.
def get_pids_by_name(process_type, debug):
    pids_command = f'pgrep {process_type}'
    pipe_pids = run_command.command_output(pids_command, debug, container_name=False)
    pids = pipe_pids.stdout
    print(constants.FULL_QUESTION_MESSAGE.format(f'There are running {process_type} processes on the host?'))
    if pids:
        relevant_pids = []
        for pid in pids:
            pid_status_path = f'/proc/{pid}/status'
            pid_status_content = commons.file_content(pid_status_path, debug, container_name=False)
            if not pid_status_content:
                return pid_status_content
            for line in pid_status_content:
                if line.startswith('NSpid:'):
                    if len(line.split('\t')) == 2:
                        relevant_pids.append(pid)
        if relevant_pids:
            print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
            pids_list = pids.split('\n')[:constants.END]
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'The following PIDs are running {process_type} processes: '
                                                            f'{pids_list}'))
            return pids_list
        else:
            print(constants.FULL_POSITIVE_RESULT_MESSAGE)
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'There are no running {process_type} processes'))
            return relevant_pids
    else:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'There are no running {process_type} processes'))
        return pids


# This function extracts the container java processes ids on the host.
def get_pids_by_name_container(process_type, debug, container_name):
    pgrep_command = f'pgrep {process_type}'
    pipe_pids_container = run_command.command_output(pgrep_command, debug, container_name)
    pids_container = pipe_pids_container.stdout
    print(constants.FULL_QUESTION_MESSAGE.format(f'There are running {process_type} processes on the {container_name} '
                                                 f'container?'))
    if pids_container:
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
        container_pids_list = pids_container.split('\n')[:constants.END]
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'The following PIDs are running {process_type} processes on '
                                                        f'the container: {container_pids_list}'))
        print(constants.FULL_QUESTION_MESSAGE.format(f'There are running {process_type} processes on the host?'))
        external_pids = get_pids_by_name(debug, process_type)
        if process_type.islower():
            process_type = process_type[constants.START].upper() + process_type[constants.FIRST:]
        else:
            process_type = process_type.lower()
        external_pids.append(get_pids_by_name(debug, process_type))
        external_pids = list(set(external_pids))
        if external_pids:
            print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'The following PIDs are running {process_type} processes '
                                                            f'on the system: {external_pids}'))
            outside_pid_of_container = []
            for outside_pid in external_pids[:constants.END]:
                pid_status_path = f'/proc/{outside_pid}/status'
                pid_status_content = commons.file_content(pid_status_path, debug, container_name=False)
                if not pid_status_content:
                    return pid_status_content
                pid_content = ''
                for field in pid_status_content:
                    if field.__contains__('NSpid:'):
                        pid_content = field
                        break
                container_pid = ''
                if len(pid_content.split('\t')) == 3:
                    container_pid = pid_content.split('\t')[constants.END]
                if container_pid in external_pids:
                    outside_pid_of_container.append(container_pid)
            return outside_pid_of_container
        else:
            print(constants.FULL_POSITIVE_RESULT_MESSAGE)
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'There are no running {process_type} processes'))
            return external_pids
    else:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'There are no running {process_type} processes'))
        return pids_container
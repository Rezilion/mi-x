"""
Support for modules written to avoid repetitive code.
"""
from modules import constants, run_command


def get_merge_dir(debug, container_name):
    """This function checks the MergeDir path of the container."""
    docker_inspect_command = constants.DOCKER_INSPECT_COMMAND.format(container_name)
    pipe_docker_inspect = run_command.command_output(docker_inspect_command, debug, container_name='')
    docker_inspect = pipe_docker_inspect.stdout
    if not docker_inspect:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Unsupported docker inspect value'))
        return constants.UNSUPPORTED
    for line in docker_inspect.split('\n'):
        if '"MergedDir"' in line:
            merged_dir_path = line.split(': ')[1][1 : -2]
            return merged_dir_path
    print(constants.FULL_EXPLANATION_MESSAGE.format('Unsupported MergeDir value'))
    return constants.UNSUPPORTED


def get_running_containers(debug):
    """This function returns a list of the running containers."""
    running_containers = []
    docker_ps_command = 'sudo docker ps -f status=running'
    pipe_docker_ps = run_command.command_output(docker_ps_command, debug, container_name='')
    docker_ps = pipe_docker_ps.stdout
    if docker_ps:
        for field in docker_ps.split('\n')[1 : -1]:
            running_containers.append(field.split(' ')[-1])
    return running_containers

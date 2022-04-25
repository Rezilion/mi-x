import Modules.constants as constants
import Modules.run_command as run_command


# This function checks the MergeDir path of the container.
def get_merge_dir(container_name, debug):
    docker_inspect_command = constants.DOCKER_INSPECT_COMMAND.format(container_name)
    pipe_docker_inspect = run_command.command_output(docker_inspect_command, debug, container_name)
    docker_inspect = pipe_docker_inspect.stdout
    if docker_inspect:
        for line in docker_inspect.split('\n'):
            if line.__contains__('"MergedDir"'):
                merged_dir_path = line.split(': ')[constants.FIRST][constants.FIRST:-2]
                return merged_dir_path
        print(constants.FULL_EXPLANATION_MESSAGE.format('Unsupported MergeDir value'))
        return constants.UNSUPPORTED
    else:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Unsupported docker inspect value'))
        return constants.UNSUPPORTED


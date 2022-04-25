import Modules.constants as constants
import Modules.os_release as os_release
import subprocess
import shlex


# This function get a system command, run it and returns the output.
def command_output(command, debug, container_name):
    if container_name:
        bash = 'bash'
        if os_release.get_field('Distribution', debug, container_name).__contains__('Alpine'):
            bash = 'sh'
        command = constants.DOCKER_EXEC_COMMAND.format(container_name, bash, command)
    converted_command = shlex.split(command)
    pipe_command = subprocess.run(converted_command, capture_output=True, text=True)
    if debug:
        print(pipe_command.stderr)
    if pipe_command.stdout.endswith('not found\n'):
        return False
    return pipe_command

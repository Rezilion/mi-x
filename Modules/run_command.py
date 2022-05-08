from Modules import constants
import subprocess
import shlex


# This function get a system command, run it and returns the output.
def command_output(command, debug, container_name):
    if container_name:
        bash = 'bash'
        docker_command = constants.DOCKER_EXEC_COMMAND.format(container_name, bash, command)
        converted_command = shlex.split(docker_command)
    else:
        converted_command = shlex.split(command)
    pipe_command = subprocess.run(converted_command, capture_output=True, text=True)
    if debug:
        print(pipe_command.stderr)
    if pipe_command.stdout.endswith('not found\n'):
        pipe_command.stdout = ''
    elif pipe_command.stdout.__contains__('/bin/bash: no such file or directory'):
        if container_name:
            bash = 'sh'
            docker_command = constants.DOCKER_EXEC_COMMAND.format(container_name, bash, command)
            converted_command = shlex.split(docker_command)
        else:
            converted_command = shlex.split(command)
        pipe_command = subprocess.run(converted_command, capture_output=True, text=True)
        if debug:
            print(pipe_command.stderr)
        if pipe_command.stdout.endswith('not found\n'):
            pipe_command.stdout = ''
        elif pipe_command.stdout.__contains__('/bin/sh: no such file or directory'):
            pipe_command.stdout = ''
    return pipe_command

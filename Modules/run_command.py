"""
Support for subprocess, shlex and other modules which written for avoiding repetitive code.
"""
import subprocess
import shlex
from Modules import constants


def command_output(command, debug, container_name):
    """This function get a system command, run it and returns the output."""
    if container_name:
        bash = 'bash'
        docker_command = constants.DOCKER_EXEC_COMMAND.format(container_name, bash, command)
        converted_command = shlex.split(docker_command)
    else:
        converted_command = shlex.split(command)
    pipe_command = subprocess.run(converted_command, capture_output=True, text=True)
    if debug:
        print(constants.FULL_EXPLANATION_MESSAGE.format(pipe_command.stderr))
    if pipe_command.stdout.endswith('not found\n'):
        pipe_command.stdout = ''
    elif '/bin/bash: no such file or directory' in pipe_command.stdout:
        if container_name:
            bash = 'sh'
            docker_command = constants.DOCKER_EXEC_COMMAND.format(container_name, bash, command)
            converted_command = shlex.split(docker_command)
        else:
            converted_command = shlex.split(command)
        pipe_command = subprocess.run(converted_command, capture_output=True, text=True)
        if debug:
            print(constants.FULL_EXPLANATION_MESSAGE.format(pipe_command.stderr))
        if pipe_command.stdout.endswith('not found\n'):
            pipe_command.stdout = ''
        elif '/bin/sh: no such file or directory' in pipe_command.stdout:
            pipe_command.stdout = ''
    return pipe_command

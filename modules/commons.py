"""
Support for os, re, semver, version from packaging and other modules which written for avoiding repetitive code.
"""
import os
from modules import run_command, constants, docker_commands, os_type, os_release


def graph_start(cve, vol_graph):
    """Graphviz start function."""
    vol_graph.attr(label=f'{cve}\n\n', labelloc='t')
    vol_graph.attr('node', shape='box', style='filled', color='red')
    vol_graph.node(constants.GRAPH_VULNERABLE)
    vol_graph.attr('node', shape='box', style='filled', color='green')
    vol_graph.node(constants.GRAPH_NOT_VULNERABLE)
    vol_graph.attr('node', shape='box', color='lightgrey')


def graph_end(vol_graph):
    """Graphviz end function."""
    try:
        vol_graph.view()
    except ValueError:
        print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format(constants.NOT_INSTALLED_MESSAGE.format('Graphviz')))

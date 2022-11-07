"""
Support for os, re, semver, version from packaging and other modules which written for avoiding repetitive code.
"""
from modules import constants


def graph_start(cve, vulnerability_graph):
    """Graphviz start function."""
    vulnerability_graph.attr(label=f'{cve}\n\n', labelloc='t')
    vulnerability_graph.attr('node', shape='box', style='filled', color='red')
    vulnerability_graph.node(constants.GRAPH_VULNERABLE)
    vulnerability_graph.attr('node', shape='box', style='filled', color='green')
    vulnerability_graph.node(constants.GRAPH_NOT_VULNERABLE)
    vulnerability_graph.attr('node', shape='box', color='lightgrey')


def graph_end(vol_graph):
    """Graphviz end function."""
    try:
        vol_graph.view()
    except ValueError:
        print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format(constants.NOT_INSTALLED_MESSAGE.format('Graphviz')))

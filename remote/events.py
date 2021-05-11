"""
Module contains a function get_events that extracts number of events from DQMIO file
"""
import logging
try:
    #pylint: disable=import-error
    import ROOT
    #pylint: enable=import-error
except ImportError:
    logging.error('Error importing ROOT')


def get_events(file_name):
    """
    Get events from a given DQMIO file
    """
    logging.info('Getting events for %s', file_name)
    try:
        root_file = ROOT.TFile.Open(file_name, 'READ')
        tree = root_file.Get("DQMData")
        return walk(tree)
    except Exception as ex:
        logging.error('Error getting events for %s file: %s', file_name, ex)

    return 0


def walk(directory):
    """
    Go through directories in depth-first way
    """
    keys = directory.GetListOfKeys()
    elements_to_enter = ('DQM', 'Run summary', 'TimerService', 'Generator', 'Particles')
    for elem in keys:
        elem_name = elem.GetName()
        item = directory.Get(elem_name)
        if item:
            if item.IsFolder():
                if elem_name in elements_to_enter or elem_name.startswith('Run '):
                    return walk(item)
            else:
                if elem_name in ('nEvt', 'event allocated'):
                    try:
                        return int(item.GetEntries())
                    except Exception as ex:
                        logging.error(ex)

    return 0

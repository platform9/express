def _get_val_at_path(dct, path):
    for key in path.split('.'):
        dct = dct[key]
    return dct


def keyed_list_to_dict(lst, path):
    return {_get_val_at_path(elem, path): elem
            for elem in lst}



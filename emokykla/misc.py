import itertools

# Peter Otten (python-list)

def list_partition(items, predicate=bool):
    a, b = itertools.tee((predicate(item), item) for item in items)
    return ((item for pred, item in a if not pred),
            (item for pred, item in b if pred))

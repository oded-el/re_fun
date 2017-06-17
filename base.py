def get_traces(initial_object, iterate_func):
    """
    Traces objects in graph
    :param initial_object: the object to start with
    :param iterate_func: gets an object and returns a list of new objects (most common use: next objects in graph)
                         if returns empty list, then the current object is considered to "match" or terminate the path.
    :return: list of matched/terminating objects
    """

    current_objects = []
    matching_objects = []

    current_objects.append(initial_object)

    depth = 0
    while current_objects and depth < 10:
        current_object = current_objects.pop()
        new_objects = iterate_func(current_object)
        if not new_objects:
            matching_objects.append(current_object)
        else:
            current_objects += new_objects
        depth += 1
    return matching_objects

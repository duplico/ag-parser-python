possible_aggs = []
for node in ag.nodes_iter():
    if ag.in_degree(node) != ag.out_degree(node):
        print 'no', node
        continue
    pre_edge_data = set()
    post_edge_data = set()
    for pre_edge in ag.in_edges_iter(node):
        this_edge_data = set({data['label'] for edge, data in ag.get_edge_data(*pre_edge).items()})
        pre_edge_data = pre_edge_data.union(this_edge_data)
    for post_edge in ag.out_edges_iter(node):
        this_edge_data = set({data['label'] for edge, data in ag.get_edge_data(*pre_edge).items()})
        post_edge_data = pre_edge_data.union(this_edge_data)
    print pre_edge_data == post_edge_data
    possible_aggs.append(())

    # TODO: actually, we should be doing this over EDGES, not NODES.
    # Oh well, at least this is progress.
#!/bin/python3

def generate_node(instructions, name, previous=None, repeat=False, lazyrepeat=False, minrepeat=None, maxrepeat=None, getid=None):
    condition = ''
    
    if len(instructions) == 1:
        condition = 'opcode is \'{}\''.format(instructions[0])
    else:
        conditions = []
        
        for instruction in instructions:
            conditions.append('(opcode is \'{}\')'.format(instruction))
            
        condition = ' or '.join(conditions)
        
    node_d = '{} [cond="{}"'.format(name, condition)
    
    if minrepeat is not None:
        node_d += ' minrepeat={}'.format(minrepeat)
    
    if maxrepeat is not None:
        node_d += ' maxrepeat={}'.format(maxrepeat)
    
    if repeat is not False:
        node_d += ' repeat={}'.format(repeat)
        
    if lazyrepeat is True:
        node_d += ' lazyrepeat=true'

    if getid is not None:
        node_d += ' getid="{}"'.format(getid)
            
    node_d += ']'
    
    node_l = ''
    
    if previous is not None:
        node_l = previous + ' -> ' + name
        
    return (node_d + '\n', node_l + '\n')

def concat_nodes(nodes, node):
    return (nodes[0] + node[0], nodes[1] + node[1])

def generate_md5_round0_and_1(compact=False):
    nodes = ('', '')
    getid = 'md5_heuristic' if compact else 'LibreSSL_md5_full'
    
    previous = None
    
    for i in range(32 if not compact else 16):
        round_label = 'Round{}_{}_'.format(0 if i < 16 else 1,  i % 16)
        
        nodes = concat_nodes(nodes,  generate_node(['xor'], round_label + '0', previous, getid=(getid if i == 0 else None)))
        nodes = concat_nodes(nodes,  generate_node(['mov', 'lea'], round_label + '0a', round_label + '0', '*', True))
        nodes = concat_nodes(nodes,  generate_node(['and'], round_label + '1', round_label + '0a'))
        nodes = concat_nodes(nodes,  generate_node(['mov', 'lea'], round_label + '1a', round_label + '1', '*', True))
        nodes = concat_nodes(nodes,  generate_node(['xor'], round_label + '2', round_label + '1a'))
        
        nodes = concat_nodes(nodes,  generate_node(['mov', 'lea', 'add', 'sub'], round_label + 'e', round_label + '2', '*', True))
        nodes = concat_nodes(nodes,  generate_node(['call', 'push', 'rol', 'ror'], round_label + 'r', round_label + 'e', '*', True))
        nodes = concat_nodes(nodes,  generate_node(['mov', 'lea', 'add', 'sub'], round_label + 'g', round_label + 'r', '*', True))
        
        nodes = concat_nodes(nodes, ('\n', '\n'))
        previous = round_label + 'g'
        
    return nodes

def generate_md5_round2(previous):
    nodes = ('', '')
    
    for i in range(16):
        round_label = 'Round2_{}_'.format(i)
        
        nodes = concat_nodes(nodes,  generate_node(['xor'], round_label + '0', previous))
        nodes = concat_nodes(nodes,  generate_node(['mov', 'lea'], round_label + '0a', round_label + '0', '*', True))
        nodes = concat_nodes(nodes,  generate_node(['xor'], round_label + '1', round_label + '0a'))
        
        nodes = concat_nodes(nodes,  generate_node(['mov', 'lea', 'add', 'sub'], round_label + 'e', round_label + '1', '*', True))
        nodes = concat_nodes(nodes,  generate_node(['call', 'push', 'rol', 'ror'], round_label + 'r', round_label + 'e', '*', True))
        nodes = concat_nodes(nodes,  generate_node(['mov', 'lea', 'add', 'sub'], round_label + 'g', round_label + 'r', '*', True))
        
        nodes = concat_nodes(nodes, ('\n', '\n'))
        previous = round_label + 'g'
        
    return nodes


def generate_md5_round2_compact(previous):
    nodes = ('', '')
    nodes = concat_nodes(nodes,  generate_node(['xor', 'mov', 'lea', 'add', 'ror', 'rol'], 'Round2', previous, '*', True))        
    return nodes


def generate_md5_round3(previous):
    nodes = ('', '')
    
    for i in range(16):
        round_label = 'Round3_{}_'.format(i)
        
        nodes = concat_nodes(nodes,  generate_node(['not'], round_label + '0', previous))
        nodes = concat_nodes(nodes,  generate_node(['mov', 'lea'], round_label + '0a', round_label + '0', '*', True))
        nodes = concat_nodes(nodes,  generate_node(['or'], round_label + '1', round_label + '0a'))
        nodes = concat_nodes(nodes,  generate_node(['mov', 'lea'], round_label + '1a', round_label + '1', '*', True))
        nodes = concat_nodes(nodes,  generate_node(['xor'], round_label + '2', round_label + '1a'))
        
        nodes = concat_nodes(nodes,  generate_node(['mov', 'lea', 'add', 'sub'], round_label + 'e', round_label + '2', '*', True))
        nodes = concat_nodes(nodes,  generate_node(['call', 'push', 'rol', 'ror'], round_label + 'r', round_label + 'e', '*', True))
        nodes = concat_nodes(nodes,  generate_node(['mov', 'lea', 'add', 'sub'], round_label + 'g', round_label + 'r', '*', True))
        
        nodes = concat_nodes(nodes, ('\n', '\n'))
        previous = round_label + 'g'
        
    return nodes


def generate_md5_round3_compact(previous):
    nodes = ('', '')
    nodes = concat_nodes(nodes,  generate_node(['not', 'or', 'xor', 'mov', 'lea', 'add', 'ror', 'rol'], 'Round3', previous, lazyrepeat=True, maxrepeat=200))    
    return nodes


def generate_md5_pattern_full(patternName):
    nodes = ('', '')
    
    nodes = concat_nodes(nodes,  generate_md5_round0_and_1())
    nodes = concat_nodes(nodes,  generate_md5_round2('Round1_15_g'))
    nodes = concat_nodes(nodes,  generate_md5_round3('Round2_15_g'))
    
    pattern = 'digraph {}{{\n'.format(patternName)
    pattern += nodes[0]
    pattern += nodes[1]
    pattern += '}'
    
    return pattern


def generate_md5_pattern_compact(patternName):
    nodes = ('', '')
    
    nodes = concat_nodes(nodes,  generate_md5_round0_and_1(True))
    nodes = concat_nodes(nodes,  generate_md5_round2_compact('Round0_15_g'))
    nodes = concat_nodes(nodes,  generate_md5_round3_compact('Round2'))
    
    pattern = 'digraph {}{{\n'.format(patternName)
    pattern += nodes[0]
    pattern += nodes[1]
    pattern += '}'
    
    return pattern


if __name__ == '__main__':
    print(generate_md5_pattern_full('md5_crypto_full') + '\n\n')
    print(generate_md5_pattern_compact('md5_crypto_heuristic'))
    

import sark
import idaapi
import idc
import time


def is_instruction_changing(insn, register):
    # TODO: register id is different for h/l bytes of registers to other variants
    for operand in insn.operands:
        try:
            if operand.is_write and operand.type.type == idaapi.o_reg and operand.reg is not None and sark.get_register_id(register) == operand.reg_id:
                return True
        except sark.exceptions.SarkOperandWithoutReg:
            pass

    return False


def is_block_changing(block, register):
    return any(map(lambda line: is_instruction_changing(line.insn, register), block.lines))


def get_changing_addr(block, register, from_addr=None):
    for line in block.lines:
        insn = line.insn
        if is_instruction_changing(insn, register) and line.ea > from_addr:
            return line.ea
    return None


def get_block_rename_range(block, terminating_addrs):
    for addr in terminating_addrs:
        if block.startEA <= addr < block.endEA:
            return (block.startEA, addr)
    return (block.startEA, block.endEA)


def apply_register_rename(blocks, terminating_addrs, register_name, new_name, from_addr=None):
    for block in blocks:
        rename_start, rename_end = get_block_rename_range(block, terminating_addrs)
        if rename_start <= from_addr < rename_end:
            rename_start = from_addr
        ida_func = idaapi.get_func(rename_start)
        idaapi.add_regvar(ida_func, rename_start, rename_end, register_name, new_name, '')


class TracePath(object):
    def __init__(self, nodes=None):
        self._nodes = []
        if nodes is not None:
            self._nodes += nodes

        self._terminating_addr = None

    def set_terminating_addr(self, addr):
        self._terminating_addr = addr

    def get_terminating_addr(self):
        return self._terminating_addr

    def get_nodes(self):
        return self._nodes

    def __repr__(self):
        representation = "Path[len = {}]".format(len(self.nodes))
        for block in self.nodes:
            representation += " -> {}".format(block)
        return representation

    def __str__(self):
        return self.__repr__()

    nodes = property(get_nodes)
    terminating_addr = property(get_terminating_addr, set_terminating_addr)


def add_paths(beg_path, next_path):
    if beg_path.terminating_addr is not None:
        raise RuntimeError("Can not combine path that is already terminated")

    path = TracePath()
    path.nodes.append(beg_path.nodes)
    path.nodes.append(next_path.nodes)
    path.terminating_addr = next_path.terminating_addr
    return path


def merge_paths(beg_paths, next_paths):
    merged_paths = []
    for path in beg_paths:
        for next_path in next_paths:
            merged_paths.append(add_paths(path, next_path))

    return merged_paths


def get_traces_imp(block, register, blocks_viewed=None, addr=None):
    # TODO: can we use hex-rays in the future? (idaapi.decompile)

    current_paths = []
    im_terminating = False
    if blocks_viewed is None:
        blocks_viewed = []

    path = TracePath()
    path.nodes.append(block)

    if is_block_changing(block, register):
        path.terminating_addr = get_changing_addr(block, register, addr)
        if path.terminating_addr is not None:
            im_terminating = True
    current_paths.append(path)

    blocks_viewed.append(block)
    if not im_terminating:
        new_paths = []
        for next_block in block.next:
            if next_block in blocks_viewed:
                continue

            more_paths, more_blocks = get_traces_imp(next_block, register, list(blocks_viewed))
            new_paths += merge_paths(current_paths, more_paths)
            blocks_viewed += more_blocks
        current_paths = new_paths

    return current_paths, blocks_viewed


def get_traces(block, register, addr=None):
    paths, blocks = get_traces_imp(block, register, addr=addr)
    terminating_addrs = map(lambda path: path.terminating_addr, paths)
    return (blocks, terminating_addrs)


def increment_path(path, viewed_blocks):
    last_block = path.nodes[-1]
    resulting_paths = []

    for block in last_block.next:
        if block in viewed_blocks:
            continue

        viewed_blocks.append(block)
        new_path = TracePath(path.nodes)
        new_path.nodes.append(block)
        resulting_paths.append(new_path)

    return resulting_paths


def get_traces_fast(block, register, addr=None):
    current_paths = []
    initial_path = TracePath()
    initial_path.nodes.append(block)
    initial_path.terminating_addr = get_changing_addr(block, register, addr)
    if initial_path.terminating_addr is not None:
        return [block], [initial_path.terminating_addr]

    current_paths.append(initial_path)
    viewed_blocks = [block]
    terminating_addrs = []

    while current_paths:
        #print "Current paths = {}".format(current_paths)
        path = current_paths.pop()
        #print 'Poped path = {}'.format(path)
        new_paths = increment_path(path, viewed_blocks)
        #print "Incremented to {}".format(new_paths)
        for new_path in new_paths:
            #print 'Currently processing {}'.format(new_path)
            new_path.terminating_addr = get_changing_addr(new_path.nodes[-1], register, addr)
            if new_path.terminating_addr is None:
                #print 'Not terminating'
                current_paths.append(new_path)
            else:
                #print 'Terminating'
                terminating_addrs.append(new_path.terminating_addr)

    return viewed_blocks, terminating_addrs


def rename_register(register_name, new_name):
    blocks, terminating_addrs = get_traces_fast(sark.CodeBlock(id_ea=idc.here()), register_name, idc.here())
    apply_register_rename(blocks, terminating_addrs, register_name, new_name, idc.here())


class RenameRegisterHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        name = idc.AskIdent('', 'Enter desired variable name: ')
        reg = idaapi.get_highlighted_identifier()
        try:
            sark.get_register_id(reg)
            rename_register(reg, name)
            return 1
        except sark.exceptions.SarkInvalidRegisterName:
            print 'Invalid register'

        return 0

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


rename_register_action_description = idaapi.action_desc_t(
    'rename:register',
    'Renames a variable until assignment paths',
    RenameRegisterHandler(),
    'Ctrl+R'
)

idaapi.register_action(rename_register_action_description)


class Hooks(idaapi.UI_Hooks):
    def finish_populating_tform_popup(self, form, popup):
        if idaapi.get_tform_type(form) == idaapi.BWN_DISASM:
            idaapi.attach_action_to_popup(form, popup, "rename:register", "Advanced/")


hooks = Hooks()
hooks.hook()
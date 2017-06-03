import sark
import idaapi
import idc


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
    def __init__(self, node=None):
        self._node = node
        self._terminating_addr = None

    def set_terminating_addr(self, addr):
        self._terminating_addr = addr

    def get_terminating_addr(self):
        return self._terminating_addr

    def get_node(self):
        return self._node

    def set_node(self, new_node):
        self._node = new_node

    def __repr__(self):
        return "Path[{}]".format(self.node)

    def __str__(self):
        return self.__repr__()

    node = property(get_node, set_node)
    terminating_addr = property(get_terminating_addr, set_terminating_addr)


def block_in_blocks(block_to_check, blocks):
    for block in blocks:
        if block.startEA == block_to_check.startEA and block.endEA == block_to_check.endEA:
            return True
    return False


def increment_path(path, viewed_blocks):
    last_block = path.node
    resulting_paths = []

    for block in last_block.next:
        if block_in_blocks(block, viewed_blocks):
            continue

        viewed_blocks.append(block)
        new_path = TracePath()
        new_path.node = block
        resulting_paths.append(new_path)

    return resulting_paths


def get_traces_fast(block, register, addr=None):
    current_paths = []
    initial_path = TracePath()
    initial_path.node = block
    initial_path.terminating_addr = get_changing_addr(block, register, addr)
    if initial_path.terminating_addr is not None:
        return [block], [initial_path.terminating_addr]

    current_paths.append(initial_path)
    viewed_blocks = [block]
    terminating_addrs = []

    while current_paths:
        path = current_paths.pop()
        new_paths = increment_path(path, viewed_blocks)
        for new_path in new_paths:
            new_path.terminating_addr = get_changing_addr(new_path.node, register, addr)
            if new_path.terminating_addr is None:
                current_paths.append(new_path)
            else:
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
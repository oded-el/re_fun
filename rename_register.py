import sark
import idaapi
import idc
import base


class BlockRegisterUsage(object):

    def __init__(self, block, usage_start=None, usage_end=None):
        self._block = block
        if usage_start is None:
            usage_start = block.startEA
        if usage_end is None:
            usage_end = block.endEA

        self._start = usage_start
        self._end = usage_end

    @property
    def block(self):
        return self._block

    @block.setter
    def block(self, new_block):
        self._block = new_block

    @property
    def usage_start(self):
        return self._start

    @usage_start.setter
    def usage_start(self, new_start):
        self._start = new_start

    @property
    def usage_end(self):
        return self._end

    @usage_end.setter
    def usage_end(self, new_end):
        self._end = new_end

    def __eq__(self, other):
        return self.block == other.block

    def __repr__(self):
        return '[{}: {}-{}]'.format(self._block, hex(self._start), hex(self._end))

    def __str__(self):
        return self.__repr__()


class UsagePath(object):

    def __init__(self, start=None):
        if start is None:
            start = []
        else:
            start = [start]

        self._path = start

    def __iadd__(self, other):
        self._path = self._path + other.path
        return self

    def add(self, block):
        self._path.append(block)

    @property
    def path(self):
        return self._path

    def get_last(self):
        return self._path[-1]

    def __repr__(self):
        return str(self._path)

    def __str__(self):
        return self.__repr__()


def is_instruction_changing(insn, register):
    # TODO: register id is different for h/l bytes of registers to other variants
    for operand in insn.operands:
        try:
            if operand.is_write and operand.type.type == idaapi.o_reg and operand.reg is not None and sark.get_register_id(register) == operand.reg_id:
                return True
        except sark.exceptions.SarkOperandWithoutReg:
            pass

    return False


def apply_register_rename(rename_blocks, register_name, new_name):
    for rename_block in rename_blocks:
        if rename_block.usage_start == rename_block.usage_end:
            continue

        ida_func = idaapi.get_func(rename_block.block.startEA)
        regvar_result = idaapi.add_regvar(
            ida_func,
            rename_block.usage_start,
            rename_block.usage_end,
            register_name,
            new_name,
            ''
        )

        # TODO: how do we handle proper duplicate blocks/block already with renamed compared to real invalid name
        if idaapi.REGVAR_ERROR_OK != regvar_result and idaapi.REGVAR_ERROR_NAME != regvar_result:
            raise RuntimeError("Failed applying rename to range {}-{}, error={}".format(
                hex(rename_block.usage_start),
                hex(rename_block.usage_end),
                regvar_result)
            )


def rename_iteration(path, register_name, viewed_blocks):
    block_register = path.get_last()
    viewed_blocks.append(block_register)

    def is_relevant_line(line):
        return block_register.usage_start < line.ea < block_register.usage_end

    is_changing = False
    for line in filter(is_relevant_line, block_register.block.lines):
        if is_instruction_changing(line.insn, register_name):
            is_changing = True
            block_register.usage_end = line.ea
            break

    if is_changing:
        return []

    next_paths = []
    for block in block_register.block.next:
        usage_block = BlockRegisterUsage(block)
        if usage_block in viewed_blocks:
            continue

        new_path = UsagePath()
        new_path += path
        new_path.add(usage_block)
        next_paths.append(new_path)

    return next_paths


def reverse_rename_iteration(path, register_name, viewed_blocks):
    block_register = path.get_last()
    viewed_blocks.append(block_register)

    def is_relevant_line(line):
        return block_register.usage_start < line.ea < block_register.usage_end

    is_changing = False
    for line in reversed(filter(is_relevant_line, block_register.block.lines)):
        if is_instruction_changing(line.insn, register_name):
            is_changing = True
            block_register.usage_start = line.ea
            break

    if is_changing:
        return []

    next_paths = []
    for block in block_register.block.prev:
        usage_block = BlockRegisterUsage(block)
        if usage_block in viewed_blocks:
            continue

        new_path = UsagePath()
        new_path += path
        new_path.add(usage_block)
        next_paths.append(new_path)

    return next_paths


def rename_register(register_name, new_name):
    current_block = UsagePath(BlockRegisterUsage(sark.CodeBlock(idc.here()), usage_start=idc.here()))
    current_reverse_block = UsagePath(BlockRegisterUsage(sark.CodeBlock(idc.here()), usage_end=idc.here()))
    viewed_blocks = []
    backwards_viewed_blocks = []
    forward_iteration = lambda b: rename_iteration(b, register_name, viewed_blocks)
    backwards_iteration = lambda b: reverse_rename_iteration(b, register_name, backwards_viewed_blocks)

    traces = base.get_traces(current_block, forward_iteration)
    reverse_traces = base.get_traces(current_reverse_block, backwards_iteration)

    for trace in traces:
        apply_register_rename(trace.path, register_name, new_name)

    for reverse_trace in reverse_traces:
        apply_register_rename(reverse_trace.path, register_name, new_name)


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
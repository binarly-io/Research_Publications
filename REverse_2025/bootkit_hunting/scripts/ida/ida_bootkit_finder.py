'''
This IDAPython script detects clearing of WP bit in CR0 register, often implemented in bootkits
'''

from idc import *
import idaapi, idautils

from ida_hexrays import *
import ida_auto, ida_loader, ida_idp, ida_kernwin

import os, bisect

g_debug = False
#g_debug = True
g_CACHE = True # decompiler cache
g_range_threshold = 0x160 # value taken from Bootkitty sample (wide due to some debug messages)

ERR_DECOMPILE_FAILED = -1

g_code_patching_ea = []

def info(msg):
    print("\033[34m\033[1m[*]\033[0m {}".format(msg))

def success(msg):
    print("\033[32m\033[1m[+]\033[0m {}".format(msg))
    
def error(msg):
    print("\033[31m\033[1m[!]\033[0m {}".format(msg))

def debug(msg):
    if g_debug:
        print("\033[33m\033[1m[D]\033[0m {}".format(msg))


class wp_disable_finder_t(ctree_visitor_t):

    def __init__(self, fva):
        
        #ctree_visitor_t.__init__(self, CV_FAST)
        ctree_visitor_t.__init__(self, CV_PARENTS)
        #ctree_visitor_t.__init__(self, CV_PARENTS | CV_POST | CV_RESTART)
        
        self.fva = fva
        self.wp_disable_eas = []
        self.wp_enable_eas = []
        self.cr0_var_names = []

    def visit_expr(self, expr):
        
        if expr.op == cot_call:

            # Find AsmWriteCr0 or inline __writecr0 disabling the WP bit in CR0
            if get_name(expr.x.obj_ea) == 'AsmWriteCr0' or expr.x.helper == '__writecr0':
                arg = expr.a.at(0)

                if arg.op == cot_band and arg.x.op == cot_var and arg.y.op == cot_num:
                    var = arg.x.v.getv()
                    num = arg.y.n._value
                    if num in [0xFFFFFFFFFFFEFFFF, 0xFFFEFFFF]:
                        info(f'{expr.ea:#x}: clearing WP bit in CR0')
                        if expr.ea not in self.wp_disable_eas:
                            bisect.insort(self.wp_disable_eas, expr.ea)
                            self.cr0_var_names.append(var.name)

                elif arg.op == cot_bor and arg.y.op == cot_num:
                    num = arg.y.n._value
                    if num == 0x10000:
                        info(f'{expr.ea:#x}: setting WP bit in CR0 (| 0x10000)')
                        if expr.ea not in self.wp_enable_eas:
                            bisect.insort(self.wp_enable_eas, expr.ea)

                elif arg.op == cot_var:
                    var = arg.v.getv().name
                    if var in self.cr0_var_names:
                        info(f'{expr.ea:#x}: restoring WP bit in CR0 (just using the same var)')
                        if expr.ea not in self.wp_enable_eas:
                            bisect.insort(self.wp_enable_eas, expr.ea)

        return 0

    def get_ranges(self):

        if self.wp_disable_eas and self.wp_enable_eas:
            if len(self.wp_disable_eas) != len(self.wp_enable_eas):
                # e.g., switch statement (disable in each case, enable once at the end)
                error(f'{self.fva:#x} (get_ranges): Number of disable/enable WP instructions does not match')
                return None
            # Make pairs with (disable, enable)
            ranges = list(zip(self.wp_disable_eas, self.wp_enable_eas))
            debug(f'{self.fva:#x} (get_ranges): ranges = {[(hex(d), hex(e)) for (d, e) in ranges]}')            
            for (disable, enable) in ranges:
                # Each list is sorted when adding, so just check disable < enable in each index
                if disable >= enable:
                    error(f'{self.fva:#x} (get_ranges): disable >= enable')
                    return None
                # Check if the range size is too big
                if enable - disable > g_range_threshold:
                    error(f'{self.fva:#x} (get_ranges): enable - disable > g_threshold')
                    return None
            return ranges
        else:
            #debug(f'{self.fva:#x}: No code disabling write-protect found')
            return None

class code_patch_finder_t(ctree_visitor_t):

    def __init__(self, fva, ranges):
        
        #ctree_visitor_t.__init__(self, CV_FAST)
        ctree_visitor_t.__init__(self, CV_PARENTS)
        #ctree_visitor_t.__init__(self, CV_PARENTS | CV_POST | CV_RESTART)
        
        self.fva = fva
        self.ranges = ranges
        self.patch_locs = []

    def visit_expr(self, expr):
        
        if expr.op == cot_call:

            # Is the address within one of the ranges?
            for (disable, enable) in self.ranges:
                if disable < expr.ea < enable:
                    #debug(f'{self.fva:#x}: {disable:#x} < {expr.ea:#x} < {enable:#x}')

                    # Find memcpy-like call with 3 arguments (dst, src, size) then detect suspicious code bytes for patching
                    # e.g., InternalMemCopyMem, qmemcpy (rep movsb)
                    # Note: The decompiler sometimes mistakes the number of arguments (e.g., 4, not 3)
                    if expr.a.size() >= 3 and expr.a.at(2).op == cot_num:
                        debug(f'{expr.ea:#x}: suspicious memcpy-like call with 3 or more arguments found')
                        src = expr.a.at(1)
                        size = expr.a.at(2).n._value

                        # Take the 2nd argument pointer
                        ea_bytes = None
                        if src.op == cot_obj:
                            ea_bytes = src.obj_ea
                        elif src.op == cot_ref and src.x.op == cot_obj:
                            ea_bytes = src.x.obj_ea
                        elif src.op == cot_cast:
                            if src.x.op == cot_obj:
                                ea_bytes = src.x.obj_ea
                            elif src.x.op == cot_ref and src.x.x.op == cot_obj:
                                ea_bytes = src.x.x.obj_ea
                        
                        if ea_bytes:
                            # Validate the bytes size then make code
                            if ida_bytes.next_that(ea_bytes, next_head(ea_bytes) + 1, testf) - ea_bytes >= size:
                                ida_bytes.del_items(ea_bytes)
                                if ida_ua.create_insn(ea_bytes):
                                    info(f'{expr.ea:#x}: memcpy-like call within one of the ranges, whose source can be decoded as instructions')

                                    # Decode the instructions and revalidate the size
                                    ea = ea_bytes
                                    val_size = 0
                                    insn = ida_ua.insn_t()
                                    while ea < ea_bytes + size:
                                        res_size = ida_ua.decode_insn(insn, ea)
                                        if res_size:
                                            debug(f'{ea:#x} ({res_size:3}): {generate_disasm_line(ea, 0)}')
                                            val_size += res_size
                                            ea += res_size
                                        else:
                                            break
                                    if val_size == size:
                                        success(f'{self.fva:#x}: code patching found at {expr.ea:#x} (source = {ea_bytes:#x}) and decoded instructions size ({size}) matched)')
                                        self.patch_locs.append(expr.ea)
                                        add_bookmark(expr.ea, 'Code patching in write-protect disabled state')
                                    else:
                                        error(f'{self.fva:#x}: code patching found at {expr.ea:#x} (source = {ea_bytes:#x}) but partially decoded ({val_size=}, {size=})')

        return 0
    
    def get_patch_locations(self):

        return self.patch_locs


# test function for ida_bytes.next_that
def testf(flags):

    return ida_bytes.has_xref(flags) or ida_bytes.has_any_name(flags)

# Ported from examples/hexrays/decompile_entry_points.py
def init_hexrays():
    
    ALL_DECOMPILERS = {
        ida_idp.PLFM_386: "hexrays",
        ida_idp.PLFM_ARM: "hexarm",
        ida_idp.PLFM_PPC: "hexppc",
        ida_idp.PLFM_MIPS: "hexmips",
    }
    cpu = ida_idp.ph.id
    decompiler = ALL_DECOMPILERS.get(cpu, None)
    
    if not decompiler:
        error("No known decompilers for architecture with ID: %d" % ida_idp.ph.id)
        return False
        
    if ida_ida.inf_is_64bit():
        if cpu == ida_idp.PLFM_386:
            decompiler = "hexx64"
        else:
            decompiler += "64"

    # In IDA9, hexx64 is used for 32-bit binaries
    if cpu == ida_idp.PLFM_386 and ida_kernwin.get_kernel_version() == '9.0':
        decompiler = "hexx64"
    
    if ida_loader.load_plugin(decompiler) and init_hexrays_plugin():
        return True
    else:
        error('Couldn\'t load or initialize decompiler: "%s"' % decompiler)
        return False

def exit_without_change(status):

    print('-' * 50) # Differentiate the log

    # Not create/change idb
    process_config_line("ABANDON_DATABASE=YES")

    # Exit with the status code
    qexit(status)

def get_ctree_root(ea, cache=True):
    
    cfunc = None
    #debug(f'{ea:#x} decompiling...')
    try:
        if cache:
            cfunc = decompile(ea)
        else:
            cfunc = decompile(ea, flags=DECOMP_NO_CACHE)        
    except:
        error('Decompilation of a function {:#x} failed'.format(ea))

    return cfunc

def add_bookmark(ea, comment):
    
    last_free_idx = -1
    for i in range(0, 1024):
        slot_ea = get_bookmark(i)
        if slot_ea == BADADDR or slot_ea == ea:
            # empty slot found or overwrite existing one
            last_free_idx = i
            break
        
    # Check Empty Slot
    if last_free_idx < 0:
        return False
    
    # Register Slot
    put_bookmark(ea, 0, 0, 0, last_free_idx, comment)
    
    return True

def main():

    '''
            -1: Decompiler initialization failure
             0: The execution works but no indicator found
         100-?: Bootkit indicators found (100 * number of indicators)
    '''
    status = 0
    target_file_name = os.path.basename(get_input_file_path())

    info(f'{target_file_name}: Start')
    print('-' * 100)

    if ida_kernwin.cvar.batch: # batch mode execution

        # Wait until the initial auto analysis is finished
        ida_auto.auto_wait()

        # We need to load the decompiler manually
        if not init_hexrays():            
            error(f'{target_file_name}: Decompiler initialization failed. Aborted.')
            if ida_kernwin.get_kernel_version() == '9.0':
                return ERR_DECOMPILE_FAILED
            else:
                exit_without_change(ERR_DECOMPILE_FAILED)

    # Demangle names
    #idaapi.cvar.inf.demnames = 1
    #ida_kernwin.refresh_idaview_anyway()
    
    #fvas = [get_func_attr(get_screen_ea(), FUNCATTR_START)]
    fvas = list(idautils.Functions())

    info('Find and rename AsmReadCr0/AsmWriteCr0')
    for fva in fvas:
        if get_func_flags(fva) & (FUNC_LIB | FUNC_THUNK):
            #debug(f"{fva:#x}: skipping library or thunk function")
            continue

        cfunc = get_ctree_root(fva)
        #debug(f'{fva:#x} got cfunc')

        if cfunc and cfunc.body.op == cit_block:            
            blk = cfunc.body.cblock

            if blk.size() == 1 and blk.at(0).op == cit_return:
                ret = blk.at(0).creturn
                if ret.expr.op == cot_call and ret.expr.x.helper == '__readcr0':
                    success(f'{fva:#x}: AsmReadCr0 detected')
                    ida_name.force_name(fva, 'AsmReadCr0') # actually not used in this PoC

            elif blk.size() == 2 and blk.at(0).op == cit_expr and blk.at(1).op == cit_return:
                expr = blk.at(0).cexpr
                ret = blk.at(1).creturn
                if expr.op == cot_call and expr.x.helper == '__writecr0' and \
                    expr.a.at(0).op == cot_var and ret.expr.op == cot_var:
                    call_var = expr.a.at(0).v.getv()
                    ret_var = ret.expr.v.getv()
                    if call_var.is_arg_var and ret_var.is_arg_var and call_var.name == ret_var.name:                    
                        success(f'{fva:#x}: AsmWriteCr0 detected')
                        ida_name.force_name(fva, 'AsmWriteCr0')

    
    print('-' * 100)
    info('Identify write-protect disable/enable instructions and code patching calls')
    for fva in fvas:
        if get_func_flags(fva) & (FUNC_LIB | FUNC_THUNK):
            #debug(f"{fva:#x}: skipping library or thunk function")
            continue

        cfunc = get_ctree_root(fva)
        if cfunc:
            wpd_finder = wp_disable_finder_t(fva)            
            wpd_finder.apply_to_exprs(cfunc.body, None)
            ranges = wpd_finder.get_ranges()
            if ranges:
                cp_finder = code_patch_finder_t(fva, ranges)            
                cp_finder.apply_to_exprs(cfunc.body, None)
                locs = cp_finder.get_patch_locations()
                if locs:
                    success(f'{fva:#x}: Code patch locations found {[hex(x) for x in locs]}')
                    #print('-' * 100)
                    status = 100

    print('-' * 100)
    info(f'{target_file_name}: Done with status {status}')

    if ida_kernwin.cvar.batch:
        if ida_kernwin.get_kernel_version() == '9.0':
            return status
        else:
            exit_without_change(status)

if __name__ == '__main__':
    main()

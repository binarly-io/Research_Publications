import argparse, os, time, datetime, contextlib
import pefile

# Initialize idalib
import idapro
import idc

# Disable console messages via the msg() function
#idapro.enable_console_messages(False)
# Enable for debug
#idapro.enable_console_messages(True)

def suppress_stdout(func, *args, **kwargs):
    with open(os.devnull, 'w') as fnull:
        with contextlib.redirect_stdout(fnull):
            return func(*args, **kwargs)

g_finder_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ida_bootkit_finder.py')
g_found = []
g_error = []

ERR_DECOMPILE_FAILED = -1

g_debug = False

def info(msg):
    print("\033[34m\033[1m{}\033[0m {}".format('[*]', msg))

def success(msg):
    print("\033[32m\033[1m{}\033[0m {}".format('[+]', msg))
    
def error(msg):
    print("\033[31m\033[1m{}\033[0m {}".format('[!]', msg))

def debug(msg):
    if g_debug:
        print("\033[33m\033[1m{}\033[0m {}".format('[D]', msg))

def auto_int(x):
    return int(x, 0)        

def iter_file(d):
    
    for entry in os.listdir(d):
        if os.path.isfile(os.path.join(d, entry)):
            yield os.path.join(d, entry)

def iter_file_recursive(d):
    
    for root, dirs, files in os.walk(d):
        for file_ in files:
            yield os.path.join(root, file_)

def test():

    print(f'{idc.get_input_file_path()}: Test')

    return 0

def run_finder(target):

    # Identify x86/x64 PE/TE
    try:
        pe = pefile.PE(target)
    except pefile.PEFormatError:
        with open(target, 'rb') as f:
            if f.read(2) != b'VZ': # TE format
                error(f'{target}: Not PE/TE file')
                return 0
    else:
        if pefile.MACHINE_TYPE[pe.FILE_HEADER.Machine] not in ['IMAGE_FILE_MACHINE_I386', 'IMAGE_FILE_MACHINE_AMD64']:
            error(f'{target}: Not x86/x64 file')
            return 0
    
    # Run the finder code
    info(f'Running finder on {target}')
    idapro.open_database(target, True)
    #ida_idaapi.IDAPython_ExecScript(g_finder_path, globals())
    import ida_bootkit_finder
    if g_debug:
        ret_code = ida_bootkit_finder.main()
    else:
        ret_code = suppress_stdout(ida_bootkit_finder.main)
    idapro.close_database(save=False)

    # Print the result
    global g_found, g_error
    if ret_code == 100:
        res = "\033[32m\033[1m INDICATOR FOUND \033[0m"
        g_found.append(target)
    #elif ret_code == 100:
    #    res = "\033[33m\033[1m MESSAGE \033[0m"
    elif ret_code == 0:
        res = "\033[34m\033[1m NO INDICATOR FOUND \033[0m"
    elif ret_code == ERR_DECOMPILE_FAILED:
        res = "\033[31m\033[1m DECOMPILATION FAILED \033[0m"
        g_error.append(target)
    else:
        # probably another issue
        res = "\033[31m\033[1m UNEXPECTED STATUS {} \033[0m".format(ret_code)
        g_error.append(target)
        
    success('{}: {}'.format(target, res))

    return 1
            
def parse_args():
    global g_debug
    
    parser = argparse.ArgumentParser(description='wrapper script of ida_ioctl_propagate.py for triage', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('target', help="PE file or folder to analyze")
    parser.add_argument("-r", "--recursive", action='store_true', help="find file recursively")
    parser.add_argument("-d", "--debug", action='store_true', help="output debug message")
    
    args = parser.parse_args()    
    g_debug = args.debug
    return args

def main():

    tstart = time.time()
    info('Start')
    
    args = parse_args()
    cnt = 0

    if os.path.isfile(args.target):
        cnt += run_finder(args.target)
    
    elif os.path.isdir(args.target):
        gen_lf = iter_file_recursive if args.recursive else iter_file
        
        for t in gen_lf(args.target):
            cnt += run_finder(t)

    tdelta = datetime.timedelta(seconds=time.time()-tstart)
    info('{} analyses done in {}'.format(cnt, tdelta))
    
    if g_found:
        success('{} suspicious bootkits found:'.format(len(g_found)))
        for f in g_found:
            print(os.path.basename(f))

    if g_error:
        error('{} samples with error status:'.format(len(g_error)))
        for f in g_error:
            print(os.path.basename(f))

if ( __name__ == "__main__" ):
    main()        
        

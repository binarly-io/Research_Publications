import argparse, os, subprocess, time, datetime, ctypes
import pefile

g_finder_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ida_bootkit_finder.py')
g_ida32_path = '/Applications/IDA/ida.app/Contents/MacOS/ida' # 8.4
g_ida64_path = '/Applications/IDA/ida64.app/Contents/MacOS/ida64' # 8.4
#g_ida32_path = g_ida64_path = '/Applications/IDA90/IDA Professional 9.0.app/Contents/MacOS/ida' # 9 -> not work. We should use idalib
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

def run_finder(target, log_path):

    # Identify x86/x64 PE/TE and 64-bit
    is_64bit = False
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
        if pefile.MACHINE_TYPE[pe.FILE_HEADER.Machine] == 'IMAGE_FILE_MACHINE_AMD64':
            is_64bit = True

    # Make the command line
    ida_path = g_ida64_path if is_64bit else g_ida32_path
    if log_path:
        cmd = [ida_path, '-A', f'-S{g_finder_path}', f'-L{log_path}', target]
    else:
        cmd = [ida_path, '-A', f'-S{g_finder_path}', target]
    debug(' '.join(cmd))
    
    # Run the script
    info(f'Running finder on {target}')
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()

    # Print the result
    global g_found, g_error
    ret_code = ctypes.c_int32(proc.returncode).value
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
    parser.add_argument("-l", "--log", default=None, help="save IDA output to the log file")
    
    args = parser.parse_args()    
    g_debug = args.debug
    return args

def main():

    tstart = time.time()
    info('Start')
    
    args = parse_args()
    cnt = 0

    if os.path.isfile(args.target):
        cnt += run_finder(args.target, args.log)
    
    elif os.path.isdir(args.target):
        gen_lf = iter_file_recursive if args.recursive else iter_file
        
        for t in gen_lf(args.target):
            cnt += run_finder(t, args.log)

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
        

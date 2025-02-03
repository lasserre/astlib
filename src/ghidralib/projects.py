import typing
if typing.TYPE_CHECKING:
    import ghidra
    from ghidra.ghidra_builtins import *

import ghidra
from ghidra.base.project import GhidraProject
from ghidra.framework.model import ProjectLocator, DomainFile
from ghidra.framework.data import DefaultCheckinHandler
from ghidra.program.model.listing import Program
from ghidra.app.decompiler import DecompileOptions
from ghidra.util.exception import FileInUseException

from pathlib import Path
import uuid
import shutil
from typing import List

from .decompiler import AstDecompiler

def get_project_manager_headless() -> ghidra.framework.project.DefaultProjectManager:
    '''
    Specifically, a DefaultProjectManager handle is the only way I can find to
    create a SHARED project!
    '''
    name = f'TEMP-{str(uuid.uuid4())[:7]}'
    temporary = True    # delete the project when we close it
    tmp_proj = GhidraProject.createProject(Path.cwd(), name, temporary)
    # all this...just to get a handle to a PM because Ghidra makes things difficult
    proj_manager = tmp_proj.projectManager
    tmp_proj.close()
    return proj_manager

def is_debug_binary(bin_file:DomainFile) -> bool:
    '''
    Returns true if this file is a debug binary (determined by its name, not DWARF info)
    '''
    # check that '.' is in the text preceding '.debug' to avoid an edge case I actually
    # had where a binary was actually named "debug", giving
    #   stripped version:     0.debug
    #   debug version:        0.debug.debug
    # (this check ensures 0.debug is treated like a stripped binary)
    return str(bin_file.name).endswith('.debug') and '.' in str(bin_file.name)[:-6]

def get_all_files_in_project(proj:GhidraProject, debug_only:bool=False, strip_only:bool=False) -> List[DomainFile]:
    '''
    Collect a list of all files in this project

    debug_only: Don't include the stripped binaries
    strip_only: Don't include the debug binaries
    '''
    assert not (debug_only and strip_only), "debug_only and strip_only are mutually exclusive"

    folders = [proj.rootFolder]
    all_files = []

    while folders:
        f = folders.pop()
        all_files.extend(f.files)
        folders.extend(f.folders)

    if strip_only:
        return [f for f in all_files if not is_debug_binary(f)]
    elif debug_only:
        return [f for f in all_files if is_debug_binary(f)]

    return all_files

def locate_binaries_from_project(proj:GhidraProject, binary_list:List[str],
                                debug_only:bool=False, strip_only:bool=False) -> List[DomainFile]:
    '''
    Locate the specified list of binaries from the project, and return them as a list of DomainFiles

    binary_list: The list of specific binary names to locate (without binary id prefix or .debug suffix)
    '''
    repo_file_paths = {}  # map de-numbered name -> DomainFile paths
    for f in get_all_files_in_project(proj, debug_only=debug_only, strip_only=strip_only):
        # remove initial binary number (e.g. 4.binary_name -> binary_name)
        denumbered_name = str(f.name)[str(f.name).find('.')+1:]
        repo_file_paths[denumbered_name] = f
    return [repo_file_paths[binary] for binary in binary_list]

def locate_ghidra_binary(proj:GhidraProject, run_name:str, binid:int, debug_binary:bool) -> DomainFile:
    '''
    Locates the wildebeest binary from the given project matching the given run name,
    binary id, and selecting either the debug or stripped version as appropriate
    '''
    root_folder = proj.getRootFolder()
    proj_name = proj.project.repository.name

    matching_folders = [x for x in root_folder.getFolders() if run_name in str(x)]
    if not matching_folders:
        raise Exception(f'No matching run folder found for {run_name} in {proj_name}')
    elif len(matching_folders) > 1:
        raise Exception(f'Multiple possible matching folders for {run_name} in {proj_name}')

    run_folder = matching_folders[0]

    matching_binaries = [x for x in run_folder.getFiles() if str(x.name).startswith(f'{binid}.')]
    # NOTE - had to add the last condition for the edge case (that I have) where a binary
    # is actually named "debug" lol
    matching_debug = [x for x in matching_binaries if str(x.name).endswith('.debug') and str(x.name) != f'{binid}.debug']
    matching_stripped = [x for x in matching_binaries if x not in matching_debug]

    # print(f'Matching debug bins: {matching_debug}')
    # print(f'Matching stripped bins: {matching_stripped}')

    matches = matching_debug if debug_binary else matching_stripped
    if not matches:
        raise Exception(f'No binaries matching binary id {binid} in {run_name} in {proj_name}')
    elif len(matches) > 1:
        raise Exception(f'Multiple file matches for binary id {binid} in {run_name} in {proj_name}')

    # bin_file = root_folder.getFolder('run1.x64-gcc-O0.astera').getFile('6.fighter')
    bin_file = matches[0]
    return bin_file

def get_debug_binary(strip_binary:DomainFile):
    '''
    Get the debug version of this binary file
    '''
    matches = [f for f in strip_binary.parent.files if f.name == f'{strip_binary.name}.debug']
    if len(matches) > 1:
        raise Exception(f'Multiple possible debug file matches found for {strip_binary.name}')
    return matches[0] if matches else None

def terminate_all_checkouts(domain_file:DomainFile):
    for co in domain_file.checkouts:
        domain_file.terminateCheckout(co.checkoutId)

def verify_ghidra_revision(domain_file:DomainFile, expected_revision:int, rollback_delete:bool, terminate_checkouts:bool=False):
    '''
    Verifies this Ghidra file is at the expected revision.

    If rollback_delete is true, files beyond expected_revision will be rolled back
    by deleting revisions. Otherwise, an exception will be thrown.

    An exception will be thrown in any case if the revision is < the expected revision
    '''
    if domain_file.version != expected_revision:
        msg = f'{domain_file.name} @ version {domain_file.version} does not match expected version {expected_revision}'

        if domain_file.version > expected_revision and rollback_delete:
            print(msg)
            print(f'Rolling back {domain_file.name} from version {domain_file.version} to version {expected_revision}...')
            for v in range(domain_file.version, expected_revision, -1):
                try:
                    domain_file.delete(v)
                except FileInUseException:
                    # this is happening all the time for me when I have to kill the process
                    # during testing and leave a dangling checkout. I added terminate_checkouts for
                    # convenience so this automatically kills any leftover checkouts...in case anyone is
                    # wondering why such a thing exists later :)
                    if terminate_checkouts:
                        terminate_all_checkouts(domain_file)
                        domain_file.delete(v)   # try again now that we killed checkouts
                    else:
                        raise
        else:
            # version < expected_revision or rollback_delete is false
            raise Exception(msg)

class OpenSharedGhidraProject:
    '''
    Encapsulates the resource management required to create a temporary
    shared project (which exists locally) that can be used inside a with
    statement but will go away afterwards
    '''
    def __init__(self, host:str, repoName:str, port:int=13100, local_dir:str=None):
        self.host = host
        self.port = port
        self.repoName = repoName
        self.local_dir = local_dir if local_dir else Path.cwd()
        self.repoAdapter = None

    def __enter__(self):
        pm = get_project_manager_headless()
        self.repoAdapter = pm.getRepositoryServerAdapter(self.host, self.port, True).getRepository(self.repoName)

        # first, create the SHARED project
        shared_pl = ProjectLocator(self.local_dir, f'{self.repoName}-temp-{str(uuid.uuid4())[:5]}')
        shared_proj_dir = Path(str(shared_pl.projectDir))

        # create SHARED project and close immediately (only way I can find to create a shared proj)
        pm.createProject(shared_pl, self.repoAdapter, False).close()

        # now reopen it as a GhidraProject
        self.shared_gp = GhidraProject.openProject(shared_proj_dir.parent, shared_proj_dir.stem, False)
        self.shared_proj_dir = shared_proj_dir

        if not self.repoAdapter.server.connected:
            raise Exception(f'Unable to connect to Ghidra repo {self.repoName} at {self.host}:{self.port}')

        return self.shared_gp

    def __exit__(self, etype, value, traceback):
        self.shared_gp.close()
        shutil.rmtree(self.shared_proj_dir)
        self.shared_proj_dir.with_suffix('.gpr').unlink(missing_ok=True)
        self.repoAdapter.disconnect()

class GhidraCheckoutProgram:
    '''
    Checks out the given file during __enter__ and checks in any changes on exit
    '''
    def __init__(self, proj:GhidraProject, domain_file:DomainFile, read_only:bool=False, exclusive:bool=False,
                task_monitor=None,
                bid:int=-1, decomp_timeout_sec:int=240, decomp_opts:DecompileOptions=None) -> None:
        self.proj = proj
        self.domain_file = domain_file
        self.read_only = read_only
        self.exclusive = exclusive
        self.monitor = task_monitor
        self.checkin_msg = ''   # client code should set this inside the with block to set their commit msg
        self.program:Program = None

        # decompiler options
        self.bid = bid
        self.decomp_timeout_sec = decomp_timeout_sec
        self.decomp_opts = decomp_opts

        self._decompiler:AstDecompiler = None

    @property
    def decompiler(self) -> AstDecompiler:
        '''Handle to the AST decompiler for this program'''
        return self._decompiler

    def __enter__(self) -> 'GhidraCheckoutProgram':
        success = self.domain_file.checkout(self.exclusive, self.monitor)
        if not success:
            raise Exception(f'Unable to checkout domain file {self.domain_file}')

        self.program = self.proj.openProgram(self.domain_file.parent.pathname, self.domain_file.name, self.read_only)

        # init decompiler
        self._decompiler = AstDecompiler(self.program, self.bid, self.decomp_timeout_sec, self.decomp_opts)
        self._decompiler.__enter__()

        return self

    def __exit__(self, etype, value, traceback):

        self._decompiler.__exit__(etype, value, traceback)
        self._decompiler = None

        # NOTE: [domain_file|program].changed property only works BEFORE YOU SAVE THE FILE!
        # -> client code should NOT save...otherwise we won't know to check it in
        # -> if the client wants to abort/don't save changes, they can CLOSE THE PROGRAM (co.proj.close(co.program))

        if self.domain_file.open:
            # not closed - check for changes...
            if self.domain_file.changed:
                print(f'PROGRAM CHANGED - CHECKING IN')
                self.proj.save(self.program)
                self.proj.close(self.program)
                self.domain_file.checkin(DefaultCheckinHandler(self.checkin_msg, False, False), True, None)
            else:
                print(f'no change detected from program.changed, skipping checkin')
                self.proj.close(self.program)
                self.domain_file.undoCheckout(False)
        else:
            self.domain_file.undoCheckout(False)

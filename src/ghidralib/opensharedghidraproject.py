import typing
if typing.TYPE_CHECKING:
    import ghidra
    from ghidra.ghidra_builtins import *

import ghidra
from ghidra.base.project import GhidraProject
from ghidra.framework.model import ProjectLocator

from pathlib import Path
import uuid
import shutil

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

        return self.shared_gp

    def __exit__(self, etype, value, traceback):
        self.shared_gp.close()
        shutil.rmtree(self.shared_proj_dir)
        self.shared_proj_dir.with_suffix('.gpr').unlink(missing_ok=True)
        self.repoAdapter.disconnect()

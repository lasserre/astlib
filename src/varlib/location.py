from typing import List

class LocationType:
    Register = 'reg'
    Stack = 'stack'
    Memory = 'mem'

    @staticmethod
    def get_list() -> List[str]:
        return [LocationType.Register,
                LocationType.Stack,
                LocationType.Memory]

class Location:
    '''
    Encapsulates the location of a variable, whether it be in a register, memory,
    or relative to the stack
    '''
    def __init__(self, loc_type:str, reg_name:str='', offset:int=None) -> None:
        self.loc_type = loc_type
        self.reg_name = reg_name.lower()    # make register casing consistent
        self.offset = offset

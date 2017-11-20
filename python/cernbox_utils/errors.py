class CmdError(Exception):
    pass

class CmdBadRequestError(CmdError):
    def __init__(self,msg):
        self.msg=msg


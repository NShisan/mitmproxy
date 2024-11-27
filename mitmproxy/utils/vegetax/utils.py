import  os
def GetCurrDir(isDev:bool)->str:
    currDir=os.path.dirname(os.path.realpath(__file__))
    if isDev:
        currDir=currDir.split("mitmproxy-vegetax")[0]
    else:
        currDir=currDir.split("webClone")[0]
    return currDir

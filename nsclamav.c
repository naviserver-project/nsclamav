/*
 * Copyright (c) 2001 Vlad Seryakov
 * All rights reserved.
 * 
 */

/*
 * nsclamav.c -- Interface to ClamAV antivirus library
 *
 *  ns_clamav usage:
 *
 *    ns_clamav scanfile path
 *      checks file for virues 
 *      returns list with detected virus names
 *
 *    ns_clamav scanbuff string
 *      checks string buffer for viruses
 *
 */

#include "ns.h"
#include "clamav.h"

static int ClamAvInterpInit(Tcl_Interp *interp,void *context);
static int ClamAvCmd(void *context,Tcl_Interp *interp,int objc,Tcl_Obj * CONST objv[]);

static struct cl_node *ClamAvRoot = 0;
static struct cl_limits ClamAvLimits;

NS_EXPORT int Ns_ModuleVersion = 1;

NS_EXPORT int
Ns_ModuleInit(char *server, char *module)
{
    char *path,*db;
    int rc,virnum;

    if(ClamAvRoot) return NS_OK;

    path = Ns_ConfigGetPath(server,module,NULL);

    if(!(db = Ns_ConfigGet(path,"dbdir"))) db = cl_retdbdir();
    if((rc = cl_loaddbdir(db,&ClamAvRoot,&virnum))) {
      Ns_Log(Error,"nsclamav: failed to load db: %s",cl_strerror(rc));
      return NS_ERROR;
    }
    if((rc = cl_buildtrie(ClamAvRoot))) {
      Ns_Log(Error,"nsclamav: failed to build trie: %s",cl_strerror(rc));
      cl_freetrie(ClamAvRoot);
      return NS_ERROR;
    }
    memset(&ClamAvLimits,0,sizeof(struct cl_limits));
    if(!Ns_ConfigGetInt(path,"maxfiles",&ClamAvLimits.maxfiles)) ClamAvLimits.maxfiles = 1000;
    if(!Ns_ConfigGetInt(path,"maxfilesize",&ClamAvLimits.maxfilesize)) ClamAvLimits.maxfilesize = 10 * 1048576;
    if(!Ns_ConfigGetInt(path,"maxreclevel",&ClamAvLimits.maxreclevel)) ClamAvLimits.maxreclevel = 5;
    if(!Ns_ConfigGetInt(path,"maxratio",&ClamAvLimits.maxratio)) ClamAvLimits.maxratio = 200;
    if(!Ns_ConfigGetInt(path,"archivememlim",&ClamAvLimits.archivememlim)) ClamAvLimits.archivememlim = 0;
    Ns_Log(Notice,"nsclamav: loaded %d virues",virnum);
    return Ns_TclInitInterps(server, ClamAvInterpInit, NULL);
}

static int
ClamAvInterpInit(Tcl_Interp *interp, void *context)
{
    Tcl_CreateObjCommand(interp,"ns_clamav",ClamAvCmd,context,NULL);
    return NS_OK;
}

static int
ClamAvCmd(void *context,Tcl_Interp *interp,int objc,Tcl_Obj * CONST objv[])
{
    int rc;
    char *buf;
    const char *virname;
    unsigned long size = 0;

    enum commands {
        cmdScanBuff,
        cmdScanFile
    } cmd;
      
    static char *sCmd[] = {
        "scanbuff",
        "scanfile",
        0
    };

    if(objc < 3) {
      Tcl_AppendResult(interp, "wrong # args: should be ns_savi command ?args ...?",0);
      return TCL_ERROR;
    }
    if(Tcl_GetIndexFromObj(interp,objv[1],sCmd,"command",TCL_EXACT,(int *)&cmd) != TCL_OK)
      return TCL_ERROR;

    switch(cmd) {
     case cmdScanBuff:
        buf = Tcl_GetStringFromObj(objv[2],(int*)&size);
        rc = cl_scanbuff(buf,size,&virname,ClamAvRoot);
        switch(rc) {
         case CL_VIRUS:
            Tcl_AppendResult(interp,virname,0);
            break;
         case CL_CLEAN:
            break;
         default:
            Tcl_AppendResult(interp,cl_strerror(rc),0);
            return TCL_ERROR;
        }
        break;

     case cmdScanFile:
        rc = cl_scanfile(Tcl_GetString(objv[2]),&virname,&size,ClamAvRoot,&ClamAvLimits,CL_ARCHIVE|CL_MAIL|CL_OLE2);
        switch(rc) {
         case CL_VIRUS:
            Tcl_AppendResult(interp,virname,0);
            break;
         case CL_CLEAN:
            break;
         default:
            Tcl_AppendResult(interp,cl_strerror(rc),0);
            return TCL_ERROR;
        }
        break;
    }
    return TCL_OK;
}

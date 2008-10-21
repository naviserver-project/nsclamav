/* 
 * The contents of this file are subject to the Mozilla Public License
 * Version 1.1(the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 * http://www.mozilla.org/.
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis,WITHOUT WARRANTY OF ANY KIND,either express or implied. See
 * the License for the specific language governing rights and limitations
 * under the License.
 * 
 * Alternatively,the contents of this file may be used under the terms
 * of the GNU General Public License(the "GPL"),in which case the
 * provisions of GPL are applicable instead of those above.  If you wish
 * to allow use of your version of this file only under the terms of the
 * GPL and not to allow others to use your version of this file under the
 * License,indicate your decision by deleting the provisions above and   
 * replace them with the notice and other provisions required by the GPL.
 * If you do not delete the provisions above,a recipient may use your
 * version of this file under either the License or the GPL.
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
 *  Author Vlad Seryakov vlad@crystalballinc.com
 *
 */

#include "ns.h"
#include "clamav.h"

static int ClamAvInterpInit(Tcl_Interp * interp, void *context);
static int ClamAvCmd(void *context, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[]);

static struct cl_node *ClamAvRoot = 0;
static struct cl_limits ClamAvLimits;

NS_EXPORT int Ns_ModuleVersion = 1;

NS_EXPORT int Ns_ModuleInit(char *server, char *module)
{
    char *path, *db;
    int rc, flags = 0;
    unsigned int virnum;

    if (ClamAvRoot) {
        return NS_OK;
    }

    path = Ns_ConfigGetPath(server, module, NULL);

    memset(&ClamAvLimits, 0, sizeof(struct cl_limits));
    ClamAvLimits.maxfiles = Ns_ConfigIntRange(path, "maxfiles", 1000, 0, 1000000);
    ClamAvLimits.maxfilesize = Ns_ConfigIntRange(path, "maxfilesize", 10 * 1048576, 0, 1000 * 1048576);
    ClamAvLimits.maxreclevel = Ns_ConfigIntRange(path, "maxreclevel", 5, 0, 100);
    ClamAvLimits.archivememlim = Ns_ConfigIntRange(path, "archivememlim", 0, 0, 10000);

    if (!(db = Ns_ConfigGetValue(path, "dbdir"))) {
        db = (char *) cl_retdbdir();
    }

    if ((rc = cl_load(db, &ClamAvRoot, &virnum, CL_DB_STDOPT|flags))) {
        Ns_Log(Error, "nsclamav: failed to load db: %s", cl_strerror(rc));
        return NS_ERROR;
    }

    if ((rc = cl_build(ClamAvRoot))) {
        Ns_Log(Error, "nsclamav: failed to build trie: %s", cl_strerror(rc));
        cl_free(ClamAvRoot);
        return NS_ERROR;
    }

    Ns_Log(Notice, "nsclamav: loaded %d virues", virnum);
    Ns_TclRegisterTrace(server, ClamAvInterpInit, 0, NS_TCL_TRACE_CREATE);
    return NS_OK;
}

static int ClamAvInterpInit(Tcl_Interp * interp, void *context)
{
    Tcl_CreateObjCommand(interp, "ns_clamav", ClamAvCmd, context, NULL);
    return NS_OK;
}

static int ClamAvCmd(void *context, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[])
{
    int rc, fd, cmd, bsize;
    char *buf, tmpfile[128];
    const char *virname;
    unsigned long size = 0;

    enum commands {
        cmdScanBuff,
        cmdScanFile
    };

    static const char *sCmd[] = {
        "scanbuff",
        "scanfile",
        0
    };

    if (objc < 3) {
        Tcl_AppendResult(interp, "wrong # args: should be ns_clamav command ?args ...?", 0);
        return TCL_ERROR;
    }
    if (Tcl_GetIndexFromObj(interp, objv[1], sCmd, "command", TCL_EXACT, (int *) &cmd) != TCL_OK) {
        return TCL_ERROR;
    }

    switch (cmd) {
    case cmdScanBuff:
        buf = Tcl_GetStringFromObj(objv[2], (int *) &bsize);
        tmpnam(tmpfile);
        fd = open(tmpfile, O_CREAT|O_RDWR, 0644);
        if (fd < 0) {
            Tcl_AppendResult(interp, strerror(errno), 0);
            return TCL_ERROR;
        }
        write(fd, buf, bsize);
        unlink(tmpfile);
        rc = cl_scandesc(fd, &virname, &size, ClamAvRoot, &ClamAvLimits, CL_SCAN_STDOPT);
        close(fd);
        switch (rc) {
        case CL_VIRUS:
            Tcl_AppendResult(interp, virname, 0);
            break;

        case CL_CLEAN:
            break;

        default:
            Tcl_AppendResult(interp, cl_strerror(rc), 0);
            return TCL_ERROR;
        }
        break;

    case cmdScanFile:
        rc = cl_scanfile(Tcl_GetString(objv[2]), &virname, &size, ClamAvRoot, &ClamAvLimits, CL_SCAN_STDOPT);
        switch (rc) {
        case CL_VIRUS:
            Tcl_AppendResult(interp, virname, 0);
            break;

        case CL_CLEAN:
            break;

        default:
            Tcl_AppendResult(interp, cl_strerror(rc), 0);
            return TCL_ERROR;
        }
        break;
    }
    return TCL_OK;
}

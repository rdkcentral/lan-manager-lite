/************************************************************************************
  If not stated otherwise in this file or this component's Licenses.txt file the
  following copyright and licenses apply:

  Copyright 2018 RDK Management

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
**************************************************************************/
/*********************************************************************************

    description:

        This is the template file of ssp_main.c for XxxxSsp.
        Please replace "XXXX" with your own ssp name with the same up/lower cases.

  ------------------------------------------------------------------------------

    revision:

        09/08/2011    initial revision.

**********************************************************************************/


#ifdef __GNUC__
#ifndef _BUILD_ANDROID
#include <execinfo.h>
#endif
#endif

#include "telemetry_busmessage_sender.h"
#include "lm_main.h"
#include <sys/stat.h>
#include "ssp_global.h"
#include "stdlib.h"
#include "ccsp_dm_api.h"
#include "cap.h"

#ifdef INCLUDE_BREAKPAD
#include "breakpad_wrapper.h"
#endif

#if defined(_ENABLE_EPON_SUPPORT_)
#include <syslog.h>
#endif
#include "safec_lib_common.h"

#define DEBUG_INI_NAME "/etc/debug.ini"
extern char*                                pComponentName;
char                                        g_Subsystem[32]         = {0};
int consoleDebugEnable = 0;
FILE* debugLogFile;
static cap_user appcaps;
int  cmd_dispatch(int  command)
{
    ANSC_STATUS  returnStatus    = ANSC_STATUS_SUCCESS;
    switch ( command )
    {
        case    'e' :

            CcspTraceInfo(("Connect to bus daemon...\n"));

            {
                char                            CName[256];
                errno_t                         rc = -1;


                rc = sprintf_s(CName, sizeof(CName), "%s%s", g_Subsystem, CCSP_COMPONENT_ID_LMLITE);
                if(rc < EOK)
                {
                    ERR_CHK(rc);
                    return -1;
                }

                ssp_Mbi_MessageBusEngage
                    ( 
                        CName,
                        CCSP_MSG_BUS_CFG,
                        CCSP_COMPONENT_PATH_LMLITE
                    );
            }

            returnStatus = ssp_create();
            if(ANSC_STATUS_SUCCESS != returnStatus)
               return -1;

            returnStatus = ssp_engage();
            if(ANSC_STATUS_SUCCESS != returnStatus)
               return -1;


            break;

        case    'm':

                AnscPrintComponentMemoryTable(pComponentName);

                break;

        case    't':

                AnscTraceMemoryTable();

                break;

        case    'c':
                
                returnStatus = ssp_cancel();
                if(ANSC_STATUS_SUCCESS != returnStatus)
                   return -1;

                break;

        default:
            break;
    }

    return 0;
}

static void _print_stack_backtrace(void)
{
#ifdef __GNUC__
#ifndef _BUILD_ANDROID
	void* tracePtrs[100];
	char** funcNames = NULL;
	int i, count = 0;

	count = backtrace( tracePtrs, 100 );
	backtrace_symbols_fd( tracePtrs, count, 2 );

	funcNames = backtrace_symbols( tracePtrs, count );

	if ( funcNames ) {
            // Print the stack trace
	    for( i = 0; i < count; i++ )
		printf("%s\n", funcNames[i] );

            // Free the string pointers
            free( funcNames );
	}
#endif
#endif
}

static void daemonize(void) {
	switch (fork()) {
	case 0:
		break;
	case -1:
		// Error
		CcspTraceInfo(("Error daemonizing (fork)! %d - %s\n", errno, strerror(
				errno)));
		exit(0);
		break;
	default:
		_exit(0);
	}

	if (setsid() < 	0) {
		CcspTraceInfo(("Error demonizing (setsid)! %d - %s\n", errno, strerror(errno)));
		exit(0);
	}

//	chdir("/");


#ifndef  _DEBUG
        int fd;
	fd = open("/dev/null", O_RDONLY);
	if (fd != 0) {
		dup2(fd, 0);
		close(fd);
	}
	fd = open("/dev/null", O_WRONLY);
	if (fd != 1) {
		dup2(fd, 1);
		close(fd);
	}
	fd = open("/dev/null", O_WRONLY);
	if (fd != 2) {
		dup2(fd, 2);
		close(fd);
	}
#endif
}

void sig_handler(int sig)
{
    if ( sig == SIGINT ) {
    	signal(SIGINT, sig_handler); /* reset it to this function */
    	CcspTraceInfo(("SIGINT received!\n"));
	exit(0);
    }
    else if ( sig == SIGUSR1 ) {
    	signal(SIGUSR1, sig_handler); /* reset it to this function */
    	CcspTraceInfo(("SIGUSR1 received!\n"));
    }
    else if ( sig == SIGUSR2 ) {
    	CcspTraceInfo(("SIGUSR2 received!\n"));
    }
    else if ( sig == SIGCHLD ) {
    	signal(SIGCHLD, sig_handler); /* reset it to this function */
    	CcspTraceInfo(("SIGCHLD received!\n"));
    }
    else if ( sig == SIGPIPE ) {
    	signal(SIGPIPE, sig_handler); /* reset it to this function */
    	CcspTraceInfo(("SIGPIPE received!\n"));
    }
    else {
    	/* get stack trace first */
    	_print_stack_backtrace();
    	CcspTraceInfo(("Signal %d received, exiting!\n", sig));
    	//exit(0);
    }

}


int main(int argc, char* argv[])
{
    BOOL                            bRunAsDaemon       = TRUE;
    int                             cmdChar            = 0;
    int                             idx = 0;

    extern ANSC_HANDLE bus_handle;
    char *subSys            = NULL;  
    DmErr_t    err;
    ANSC_STATUS   returnStatus = ANSC_STATUS_SUCCESS;
    int           ret          = 0;
    errno_t       rc           = -1;


    // Buffer characters till newline for stdout and stderr
    setlinebuf(stdout);
    setlinebuf(stderr);

    debugLogFile = stderr;
#if defined(_ENABLE_EPON_SUPPORT_)
    setlogmask(LOG_UPTO(LOG_INFO));
#endif
    appcaps.caps = NULL;
    appcaps.user_name = NULL;
    if(!drop_root_priv(&appcaps)){
	CcspTraceInfo(("droproot function failed!\n"));
    }
    clear_caps(&appcaps);
    for (idx = 1; idx < argc; idx++)
    {
        if ( (strcmp(argv[idx], "-subsys") == 0) )
        {
           if ((idx+1) < argc)
           {
               rc = strcpy_s(g_Subsystem, sizeof(g_Subsystem), argv[idx+1]);
               if(rc != EOK)
               {
                  ERR_CHK(rc);
                  CcspTraceError(("exit ERROR %s:%d\n", __FUNCTION__, __LINE__));
                  exit(1);
               }
           }
           else
           {
               CcspTraceError(("Argument missing after -subsys\n"));
           }
        }
        else if ( strcmp(argv[idx], "-c") == 0 )
        {
            bRunAsDaemon = FALSE;
        }
        else if ( (strcmp(argv[idx], "-DEBUG") == 0) )
        {
            consoleDebugEnable = 1;
            fprintf(stderr, "DEBUG ENABLE ON \n");
        }
        else if ( (strcmp(argv[idx], "-LOGFILE") == 0) )
        {
            // We assume argv[1] is a filename to open
            debugLogFile = fopen( argv[idx + 1], "a+" );

            /* fopen returns 0, the NULL pointer, on failure */
            if ( debugLogFile == 0 )
            {
                debugLogFile = stderr;
                fprintf(debugLogFile, "Invalid Entry for -LOGFILE input \n" );
            }
            else 
            {
                fprintf(debugLogFile, "Log File [%s] Opened for Writing in Append Mode \n",  argv[idx+1]);
            }

        }        
    }
    pComponentName          = CCSP_COMPONENT_NAME_LMLITE;
#ifdef INCLUDE_BREAKPAD
    breakpad_ExceptionHandler();
#endif

    t2_init("ccsp-lm-lite");

    if ( bRunAsDaemon ) 
        daemonize();

#ifndef INCLUDE_BREAKPAD
    /*signal(SIGTERM, sig_handler); NEVER Mask SIGTERM or reboot wont shutdown the process (XF3-1284) */
    signal(SIGINT, sig_handler);
    /*signal(SIGCHLD, sig_handler);*/
    signal(SIGUSR1, sig_handler);
    signal(SIGUSR2, sig_handler);

    signal(SIGSEGV, sig_handler);
    signal(SIGBUS, sig_handler);
    signal(SIGKILL, sig_handler);
    signal(SIGFPE, sig_handler);
    signal(SIGILL, sig_handler);
    signal(SIGQUIT, sig_handler);
    signal(SIGHUP, sig_handler);
#endif

    ret = cmd_dispatch('e');
    if(ret != 0)
    {
       CcspTraceError(("exit ERROR %s:%d\n", __FUNCTION__, __LINE__));
      exit(1);
    }

#ifdef _COSA_SIM_
    subSys = "";        /* PC simu use empty string as subsystem */
#else
    subSys = NULL;      /* use default sub-system */
#endif
    err = Cdm_Init(bus_handle, subSys, NULL, NULL, pComponentName);
    if (err != CCSP_SUCCESS)
    {
        fprintf(stderr, "Cdm_Init: %s\n", Cdm_StrError(err));
       exit(1);
    }
#ifdef FEATURE_SUPPORT_RDKLOG
    RDK_LOGGER_INIT();
#endif
    int chk_ret = creat("/tmp/lmlite_initialized",S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (chk_ret == -1)
    {
      CcspTraceError(("Error creating the file /tmp/lmlite_initialized.\n"));
    }
    else
    {
       close(chk_ret);
    }


    LM_main();
    if ( bRunAsDaemon )
    {
        while(1)
        {
            sleep(30);
        }
    }
    else
    {
        while ( cmdChar != 'q' )
        {
            cmdChar = getchar();

            ret = cmd_dispatch(cmdChar);
            if(ret != 0)
            {
              CcspTraceError(("exit ERROR %s:%d\n", __FUNCTION__, __LINE__));
             exit(1);
            }
        }
    }

	err = Cdm_Term();
	if (err != CCSP_SUCCESS)
	{
	fprintf(stderr, "Cdm_Term: %s\n", Cdm_StrError(err));
	exit(1);
	}

    returnStatus = ssp_cancel();
    if (ANSC_STATUS_SUCCESS != returnStatus)
    {
      CcspTraceError(("exit ERROR %s:%d\n", __FUNCTION__, __LINE__));
      exit(1);
    }


    if(debugLogFile)
    {
        fclose(debugLogFile);
    }
    
    return 0;
}


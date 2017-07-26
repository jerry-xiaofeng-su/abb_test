/***************************************************************
* Copyright 2010-2017 ABB Genway Co.,Ltd.
* FileName:    main.c
* Desc:          Logic to Device TCP demo
*
* Author:	       Jerry Su
* Date:          2017-7-21
* Notes:
*
*---------------------------------------------------------------
* Histro:
* V0.01          2017-7-21         Jerry Su      Initial Version
*
*****************************************************************/

/*----------------------------Includes----------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/tcp.h>

#include "osa/osa.h"
#include "osa/osa_debug.h"
#include "osa/osa_thr.h"
#include "osa/osa_time.h"
#include "osa/osa_mem.h"
#include "Id_ip_conf.h"
#include "network.h"
#include "logictodevice.h"
/*---------------------------Static Defines--------------------------------*/

LOCAL BOOLEAN s_ClientTaskRunning;
LOCAL OSA_MutexHndl s_ClientMutex;
LOCAL OSA_ThrHndl s_Client_hThread;

/*---------------------------Implements---------------------------------*/
void LogicClient_CreateMainThread()
{
    
}
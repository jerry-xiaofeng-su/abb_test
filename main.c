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

/*----------------------Includes----------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "osa/osa.h"
#include "osa/osa_debug.h"
#include "osa/osa_thr.h"
#include "osa/osa_time.h"
#include "network.h"
#include "logictodevice.h"

/*----------------------Implements----------------------------------------------*/

int main(int argc, const char* argv[])
{
    OSA_DBG_MSG("logic to device starting ...");
	LogicSever_CreateMainThread();
	LogicClient_CreateMainThread();
//test1
	//test2
	return 0;
}

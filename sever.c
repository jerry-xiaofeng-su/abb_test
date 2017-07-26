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

LOCAL BOOLEAN s_SeverTaskRunning;
LOCAL OSA_MutexHndl s_SeverMutex;
LOCAL OSA_ThrHndl s_Sever_hThread;

/*---------------------------Implements---------------------------------*/

LOCAL void PCMGRSYS_SendReply(int sockfd, SOCK_DATA_PACKET_T *pkg, BYTE *dataBuf, int dataLen)
{
    
    BYTE *sendBuf = NULL;
    int sendBufLen;
    SOCK_DATA_PACKET_T sendPkg = *pkg;

    sendPkg.operCode = 0x80 | sendPkg.operCode;//the highest bit is zero:request  is 1:reply
    if(dataBuf == NULL || dataLen == 0)
    {
        sendBuf = (BYTE *)&sendPkg;
		sendBufLen = sizeof(SOCK_DATA_PACKET_T);
    }
    else
    {
        sendBufLen = sizeof(SOCK_DATA_PACKET_T) + dataLen;
        sendBuf = OSA_MemMalloc(sendBufLen);
        if(sendBuf == NULL)
        {
            OSA_ERROR("Memory malloc failed");
            return -4;
        }
        MAKE_DATALEN(sendPkg.dataLen , dataLen);//slip the datalen to the array datalen
        OSA_MemCopy(sendBuf, &sendPkg, sizeof(SOCK_DATA_PACKET_T));
        OSA_MemCopy(sendBuf + sizeof(SOCK_DATA_PACKET_T), dataBuf, dataLen);
    }

    SendMsgByTCPFd(sockfd, sendBuf, sendBufLen);//socket equal the ip 

    if (sendBuf != (void *)&sendPkg)
    {
        SAFE_DELETE_MEM(sendBuf);
    }
    return OSA_SOK;
}

LOCAL void PCMGRSYS_DeviceDiscoveryACK(int sockfd, SOCK_DATA_PACKET_T *pkg, BYTE *data, int dataLen)
{
    char *tstr = "OK";

    OSA_DBG_MSG("Handle device discovery ACK: dataLen=%d", dataLen);
    PCMGRSYS_SendReply(sockfd, pkg, (BYTE *)tstr, strlen(tstr));
    close(sockfd);

}


LOCAL void PCMGRSYS_SyncTime(int sockfd, SOCK_DATA_PACKET_T *pkg, BYTE *data, int datalen)
{
    DATE_TIME_DEF t = {0};
    char tstr[16] = {0};

    OSA_TimeGetLocalDate(&t);
    snprintf(tstr, sizeof(tstr), "%04d%02d%02d%02d%02d%02d",
        t.usYear, t.usMon, t.usDay, t.usHour, t.usMin, t.usSec);//can check the length of string   
    PCMGRSYS_SendReply(sockfd, pkg, (BYTE *)tstr, strlen(tstr));
    close(sockfd);
}

LOCAL void PCMGRSYS_SysConfiguration(int sockfd, SOCK_DATA_PACKET_T *pkg, BYTE *data, int datalen)
{
    if (pkg->funcCode != 0x02)
    {
        OSA_ERROR("Wrong funcCode. expect 0x02, got %d",pkg->funcCode);
        return;
    }

    switch (pkg->operCode)
    {
        case 0x01:
            PCMGRSYS_SyncTime(sockfd, pkg, data, dataLen);
            break;
        case 0x02:
            PCMGRSYS_DeviceDiscoveryACK(sockfd, pkg, data, dataLen);
            break;
        default:
            OSA_ERROR("the operCode %d not support yet",pkg->operCode);
            break;
    }
}

LOCAL void PCMGRSYS_HandleTCPCommand(int sockfd, SOCK_DATA_PACKET_T *pkg, BYTE *data, int datalen)
{
    switch (pkg->funcCode)
    {
        case 0x01:
            OSA_DBG_MSG("The funcCode is 0x01");
            break;
        case 0x02:           
            PCMGRSYS_SysConfiguration(sockfd, pkg, data, dataLen);
            break;
        default:
            OSA_ERROR("funcCode (%d) not support yet",pkg->funcCode);
            break;
    }
}

LOCAL void Sever_WorkerThreadMain(void * arg)
{
    struct timeval tm;
	fd_set set;
	int result = -1;
	SOCK_DATA_PACKET_T cmdPacket = { { 0 }, { 0 }, 0, 0, { 0 } };
	INT32 len = 0;
	BYTE *dataBuf = NULL;
	INT32 dataLen = 0;
	int sockfd = (int)arg;

	OSA_DBG_MSG("Sever_WorkerThreadMain Entry socket=%d", sockfd);
	FD_ZERO(&set);
	FD_SET(sockfd,&set);
	tm.tv_sec = 5;
	tm.tv_usec = 0;
	result = select(sockfd + 1, &set, NULL, NULL, &tm);
	if(result <= 0)
	{
        OSA_ERROR("connected,but no data in 5s.");
		close(sockfd);
		return;
	}

	len = read(sockfd, &cmdPacket, sizeof(cmdPacket));//select >0  and socket read is able
	if(len != sizeof(cmdPacket))
	{
        OSA_ERROR("len is false");
		close(sockfd);
		return;
	}

	dataLen = MAKEFOURCC_BE(cmdPacket.dataLen[0], cmdPacket.dataLen[1], cmdPacket.dataLen[2], cmdPacket.dataLen[3]);//?
	OSA_DBG_MSG("funcCode=%d; operCode=%d; dataLen=%d", cmdPacket.funcCode, cmdPacket.operCode, cmdPacket.dataLen);
	if (dataLen > 0)
	{
        dataBuf = OSA_MemMalloc(dataLen)；
		if(NULL == dataBuf)
		{
            OSA_ERROR("Memory malloc failed");
			close(sockfd);
			return;
		}
		DoRecvDataPacketEx(sockfd, dataLen, dataBuf);
		DisplayNetCmdPacket(&cmdPacket, dataBuf, dataLen);
	}
    
    PCMGRSYS_HandleTCPCommand(sockfd, &cmdPacket, dataBuf, dataLen);
    
	SAFE_DELETE_MEM(dataBuf);
	OSA_DBG_MSG("Sever_WorkerThreadMain Exit socket=%d", sockfd);
}

LOCAL void LogicSever()
{
    struct sockaddr_in addr;
	socketlen_t len = sizeof(addr);
	int sockfd_tcp = -1;
	int sockfd = -1;
	int ret = -1;
	OSA_ThrHndl hWorkThread;

	OSA_DBG_MSG("Sever listening on port %d", SERVER_PORT);\

	sockfd_tcp = InitSocketTCP(NULL,SERVER_PORT);
	if(sockfd_tcp == -1)
	{
        OSA_ERROR("Unexpect error ...");
		ASSERT(0);
	}

	whlie(s_SeverTaskRunning)
	{
        sockfd = accept(sockfd_tcp, (struct sockaddr *)&addr, &len);
		if(sockfd <= 0)
		{
            OSA_ERROR("accept error");
			OSA_Sleep(1000);
			continue;
		}
		int flag = 1;
		ret = setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));
		if(ret < 0)
		{
            OSA_ERROR("setsockopt IPPROTO_TCP TCP_NODELAY failed.");
		}
        /* print the peer IP Address*/
		struct sockaddr_in guest;
		char guest_ip[20];
		socklen_t guest_len = sizeof(guest);
		getpeername(sockfd, (struct sockaddr *)&guest, &guest_len);
		inet_ntop(AF_INET, &guest.sin_addr, guest_ip, sizeof(guest_ip));
		OSA_DBG_MSG("Connect Remote peer IP=%s", guest_ip);

		param = sockfd;//每次都重新进入线程
		ret = OSA_ThreadCreate(&hWorkThread, (VOID *)Sever_WorkerThreadMain,(void *) param);
		if(ret != OSA_SOK)
		{
		    OSA_ERROR("Create pthread error!\n");
			continue;
		}
	}
}

void LogicSever_CreateMainThread()
{
    int ret = OSA_EFAIL;
	if (s_SeverTaskRunning)
	{
        OSA_ERROR("Sever Thread is already running");
		return;
	}
	OSA_MutexCreate(&s_SeverMutex);

	OSA_MutexLock(&s_SeverMutex);
	s_SeverTaskRunning = 1;
	OSA_MutexUnlock(&s_SeverMutex);

	ret = OSA_ThreadCreate(&s_Sever_hThread, (VOID *)LogicSever, NULL);
	if(OSA_SOK != ret)
	{
        OSA_ERROR("OSA_ThreadCreate fo LogicSever Thread failed");
		exit(1);
	}
}

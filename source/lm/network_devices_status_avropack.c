/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2016 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#include <stdio.h>
#include <assert.h>
#include <avro.h>
#include <arpa/inet.h>
#include <semaphore.h>  /* Semaphore */
#include <uuid/uuid.h>
#include "ansc_platform.h"

#include <trower-base64/base64.h>
#include "webpa_interface.h"
#include "network_devices_status_avropack.h"
#include "ccsp_lmliteLog_wrapper.h"
#include "lm_main.h"
#if SIMULATION
#include "dummy.h"
#endif
#ifdef MLT_ENABLED
#include "rpl_malloc.h"
#include "mlt_malloc.h"
#endif

#define MAGIC_NUMBER      0x85
#define MAGIC_NUMBER_SIZE 1
#define SCHEMA_ID_LENGTH  32
#define WRITER_BUF_SIZE   1024 * 30 // 30K

//      "schemaTypeUUID" : "3053b4ab-d3f9-4cc9-8c3e-f0bde4a2e6ca",
//      "schemaMD5Hash" :  "da29287d0199d6279cf934ce884426af",

uint8_t HASH[16] = {0xda, 0x29, 0x28, 0x7d, 0x01, 0x99, 0xd6, 0x27,
                    0x9c, 0xf9, 0x34, 0xce, 0x88, 0x44, 0x26, 0xaf
                   };

uint8_t UUID[16] = {0x30, 0x53, 0xb4, 0xab, 0xd3, 0xf9, 0x4c, 0xc9,
                    0x8c, 0x3e, 0xf0, 0xbd, 0xe4, 0xa2, 0xe6, 0xca
                   };


static char *macStr = NULL;
static char CpemacStr[ 32 ];
BOOL schema_file_parsed = FALSE;
char *ndsschemabuffer = NULL;
char *nds_schemaidbuffer = "3053b4ab-d3f9-4cc9-8c3e-f0bde4a2e6ca/da29287d0199d6279cf934ce884426af";
static size_t AvroSerializedSize;
static size_t OneAvroSerializedSize;
static char AvroSerializedBuf[ WRITER_BUF_SIZE ];
// schema interface 
static avro_value_iface_t  *iface =  NULL;
extern LmObjectHosts lmHosts;
extern pthread_mutex_t LmHostObjectMutex;

#ifndef UTC_ENABLE
extern int getTimeOffsetFromUtc();
#endif

// local data, load it with real data if necessary
char ReportSource[] = "LMLite";
char CPE_TYPE_EXTENDER_STRING[] = "Extender";
char CPE_TYPE_GATEWAY_STRING[] = "Gateway";

// local data, load it with real data if necessary


char* GetNDStatusSchemaBuffer()
{
  return ndsschemabuffer;
}

int GetNDStatusSchemaBufferSize()
{
int len = 0;
if(ndsschemabuffer)
	len = strlen(ndsschemabuffer);
  
return len;
}

char* GetNDStatusSchemaIDBuffer()
{
  return nds_schemaidbuffer;
}

int GetNDStatusSchemaIDBufferSize()
{
int len = 0;
if(nds_schemaidbuffer)
        len = strlen(nds_schemaidbuffer);

return len;
}

int NumberofElementsinLinkedList(struct networkdevicestatusdata* head)
{
#if SIMULATION
  return 1;  
#else
  int numelements = 0;
  struct networkdevicestatusdata* ptr  = head;
  while (ptr != NULL)
  {
    numelements++;
    ptr = ptr->next;
  }
  return numelements;
#endif
}


avro_writer_t prepare_writer_status()
{
  avro_writer_t writer;
  long lSize = 0;

  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ENTER \n", __FUNCTION__ ));

  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Avro prepares to serialize data\n"));

  if ( schema_file_parsed == FALSE )
  {
    FILE *fp;
    /* open schema file */
    fp = fopen ( NETWORK_DEVICE_STATUS_AVRO_FILENAME , "rb" );
    if ( !fp ) perror( NETWORK_DEVICE_STATUS_AVRO_FILENAME " doesn't exist."), exit(1);

    /* seek through file and get file size*/
    fseek( fp , 0L , SEEK_END);
    lSize = ftell( fp );
    if (lSize < 0)
        fclose(fp), fputs("lSize is negative value", stderr), exit(1);

    /*back to the start of the file*/
    rewind( fp );

    /* allocate memory for entire content */
    ndsschemabuffer = calloc( 1, lSize + 1 );

    if ( !ndsschemabuffer ) fclose(fp), fputs("memory alloc fails", stderr), exit(1);

    /* copy the file into the buffer */
    if ( 1 != fread( ndsschemabuffer , lSize, 1 , fp) )
      fclose(fp), free(ndsschemabuffer), ndsschemabuffer=NULL,  fputs("entire read fails", stderr), exit(1);

    fclose(fp);
    /*CID:135525 String not null terminated*/
    ndsschemabuffer[lSize] = '\0';

    avro_schema_error_t  error = NULL;

    //Master report/datum
    avro_schema_t network_device_report_schema = NULL;
    avro_schema_from_json(ndsschemabuffer, strlen(ndsschemabuffer),
                        &network_device_report_schema, &error);

    //generate an avro class from our schema and get a pointer to the value interface
    iface = avro_generic_class_from_schema(network_device_report_schema);  
    avro_schema_decref(network_device_report_schema);

    schema_file_parsed = TRUE; // parse schema file once only
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Read Avro schema file ONCE, lSize = %ld, pbuffer = 0x%lx.\n", lSize + 1, (ulong)ndsschemabuffer ));
  }
  else
  {
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Stored lSize = %ld, pbuffer = 0x%lx.\n", lSize + 1, (ulong)ndsschemabuffer ));
  }

  memset(&AvroSerializedBuf[0], 0, sizeof(AvroSerializedBuf));

  AvroSerializedBuf[0] = MAGIC_NUMBER; /* fill MAGIC number = Empty, i.e. no Schema ID */

  memcpy( &AvroSerializedBuf[ MAGIC_NUMBER_SIZE ], UUID, sizeof(UUID));

  memcpy( &AvroSerializedBuf[ MAGIC_NUMBER_SIZE + sizeof(UUID) ], HASH, sizeof(HASH));

  writer = avro_writer_memory( (char*)&AvroSerializedBuf[MAGIC_NUMBER_SIZE + SCHEMA_ID_LENGTH],
                               sizeof(AvroSerializedBuf) - MAGIC_NUMBER_SIZE - SCHEMA_ID_LENGTH );

  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : EXIT \n", __FUNCTION__ ));

  return writer;
}


/* function call from lmlite with parameters */
void network_devices_status_report(struct networkdevicestatusdata *head, BOOL extender, char* parent_mac)
{
  int i = 0, k = 0;
  int numElements = 0;
  struct networkdevicestatusdata* ptr = head;
  avro_writer_t writer;
  char * serviceName = "lmlite";
  char * dest = "event:raw.kestrel.reports.NetworkDevicesStatus";
  char * contentType = "avro/binary"; // contentType "application/json", "avro/binary"
  uuid_t transaction_id;
  char trans_id[37];
  char CpeMacHoldingBuf[ 20 ] = {0};
  unsigned char CpeMacid[ 7 ] = {0};

  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ENTER \n", __FUNCTION__ ));

  numElements = NumberofElementsinLinkedList(head);

  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, numElements = %d\n", numElements ));

  OneAvroSerializedSize = 0;

  /* goes thru total number of elements in link list */
  writer = prepare_writer_status();


  //Reset out writer
  avro_writer_reset(writer);

  //Network Device Report
  avro_value_t  adr;
  avro_generic_value_new(iface, &adr);

  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, GatewayNetworkDeviceStatusReport\tType: %d\n", avro_value_get_type(&adr)));

  avro_value_t  adrField = {0,0};
  avro_value_t array = {0,0};
  //Optional value for unions, mac address is an union
  avro_value_t optional = {0,0};

  // timestamp - long
  avro_value_get_by_name(&adr, "header", &adrField, NULL);
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
  if (adrField.iface == NULL)
  {
    CcspTraceWarning(("adrField.iface is NULL"));  
    return;
  }
  avro_value_get_by_name(&adrField, "timestamp", &adrField, NULL);
  avro_value_set_branch(&adrField, 1, &optional);
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

  struct timeval ts;
  gettimeofday(&ts, NULL);
#ifndef UTC_ENABLE
  int64_t tstamp_av_main = ((int64_t) (ts.tv_sec - getTimeOffsetFromUtc()) * 1000000) + (int64_t) ts.tv_usec;
#else
  int64_t tstamp_av_main = ((int64_t) (ts.tv_sec) * 1000000) + (int64_t) ts.tv_usec;
#endif
  tstamp_av_main = tstamp_av_main/1000;

  avro_value_set_long(&optional, tstamp_av_main );
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, timestamp = ""%" PRId64 "\n", tstamp_av_main ));
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, timestamp\tType: %d\n", avro_value_get_type(&optional)));
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

  // uuid - fixed 16 bytes
  uuid_generate_random(transaction_id); 
  uuid_unparse(transaction_id, trans_id);

  avro_value_get_by_name(&adr, "header", &adrField, NULL);
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
  avro_value_get_by_name(&adrField, "uuid", &adrField, NULL);
  avro_value_set_branch(&adrField, 1, &optional);
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
  avro_value_set_fixed(&optional, transaction_id, 16);
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, uuid\tType: %d\n", avro_value_get_type(&optional)));
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

  //source - string
  avro_value_get_by_name(&adr, "header", &adrField, NULL);
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
  avro_value_get_by_name(&adrField, "source", &adrField, NULL);
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
  avro_value_set_branch(&adrField, 1, &optional);
  avro_value_set_string(&optional, ReportSource);
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, source\tType: %d\n", avro_value_get_type(&optional)));
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));


  if ( extender == FALSE )
  {
    //cpe_id block
    /* MAC - Get CPE mac address, do it only pointer is NULL */

    memset(CpeMacHoldingBuf, 0, sizeof CpeMacHoldingBuf);
    memset(CpeMacid, 0, sizeof CpeMacid);

    if ( macStr == NULL )
    {
      macStr = getDeviceMac();
	if (macStr !=NULL )
	{
      strncpy( CpemacStr, macStr, sizeof(CpemacStr));
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Received DeviceMac from Atom side: %s\n",macStr));
   	 }
	else
	{
		CcspTraceError(("Received DeviceMac from Atom side is NULL \n"));
		return;
	}
     }	



    for (k = 0; k < 6; k++ )
    {
      /* copy 2 bytes */
      CpeMacHoldingBuf[ k * 2 ] = CpemacStr[ k * 2 ];
      CpeMacHoldingBuf[ k * 2 + 1 ] = CpemacStr[ k * 2 + 1 ];
      CpeMacid[ k ] = (unsigned char)strtol(&CpeMacHoldingBuf[ k * 2 ], NULL, 16);
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Mac address = %0x\n", CpeMacid[ k ] ));
    }

    avro_value_get_by_name(&adr, "cpe_id", &adrField, NULL);
    if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
    avro_value_get_by_name(&adrField, "mac_address", &adrField, NULL);
    if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
    avro_value_set_branch(&adrField, 1, &optional);
    avro_value_set_fixed(&optional, CpeMacid, 6);
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, mac_address\tType: %d\n", avro_value_get_type(&optional)));
    if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

    // cpe_type - string
    avro_value_get_by_name(&adr, "cpe_id", &adrField, NULL);
    if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
    avro_value_get_by_name(&adrField, "cpe_type", &adrField, NULL);
    if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
    avro_value_set_branch(&adrField, 1, &optional);
    avro_value_set_string(&optional, CPE_TYPE_GATEWAY_STRING);
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, cpe_type\tType: %d\n", avro_value_get_type(&optional)));
    if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

    // cpe_parent - Recurrsive CPEIdentifier block
    avro_value_get_by_name(&adr, "cpe_id", &adrField, NULL);
    if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
    avro_value_get_by_name(&adrField, "cpe_parent", &adrField, NULL);
    if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
    avro_value_set_branch(&adrField, 0, &optional);
    avro_value_set_null(&optional);
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, cpe_parent\tType: %d\n", avro_value_get_type(&optional)));
    if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
  }
  else
  {
    //cpe_id block
    avro_value_t parent_optional = {0,0}, parent_adrField = {0,0};

    memset(CpeMacHoldingBuf, 0, sizeof CpeMacHoldingBuf);
    memset(CpeMacid, 0, sizeof CpeMacid);

    for (k = 0; k < 6; k++ )
    {
      /* copy 2 bytes */
      CpeMacHoldingBuf[ k * 2 ] = parent_mac[ k * 3 ];
      CpeMacHoldingBuf[ k * 2 + 1 ] = parent_mac[ k * 3 + 1 ];
      CpeMacid[ k ] = (unsigned char)strtol(&CpeMacHoldingBuf[ k * 2 ], NULL, 16);
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Extender Mac address = %0x\n", CpeMacid[ k ] ));
    }

    avro_value_get_by_name(&adr, "cpe_id", &adrField, NULL);
    if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
    avro_value_get_by_name(&adrField, "mac_address", &adrField, NULL);
    if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
    avro_value_set_branch(&adrField, 1, &optional);
    avro_value_set_fixed(&optional, CpeMacid, 6);
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, mac_address\tType: %d\n", avro_value_get_type(&optional)));
    if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

    // cpe_type - string
    avro_value_get_by_name(&adr, "cpe_id", &adrField, NULL);
    if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
    avro_value_get_by_name(&adrField, "cpe_type", &adrField, NULL);
    if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
    avro_value_set_branch(&adrField, 1, &optional);
    avro_value_set_string(&optional, CPE_TYPE_EXTENDER_STRING);
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, cpe_type\tType: %d\n", avro_value_get_type(&optional)));
    if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

    // cpe_parent - Recurrsive CPEIdentifier block
    avro_value_get_by_name(&adr, "cpe_id", &adrField, NULL);
    if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
    avro_value_get_by_name(&adrField, "cpe_parent", &adrField, NULL);
    if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

    
    /* MAC - Get CPE mac address, do it only pointer is NULL */
    if ( macStr == NULL )
    {
      macStr = getDeviceMac();
	if( macStr != NULL )
		{
	strncpy( CpemacStr, macStr, sizeof(CpemacStr));
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Received DeviceMac from Atom side: %s\n",macStr));
		}
	else
		{
		CcspTraceError(("Received DeviceMac from Atom side is NULL \n"));
		return;
		}
    }

    memset(CpeMacHoldingBuf, 0, sizeof CpeMacHoldingBuf);
    memset(CpeMacid, 0, sizeof CpeMacid);

    for (k = 0; k < 6; k++ )
    {
      /* copy 2 bytes */
      CpeMacHoldingBuf[ k * 2 ] = CpemacStr[ k * 2 ];
      CpeMacHoldingBuf[ k * 2 + 1 ] = CpemacStr[ k * 2 + 1 ];
      CpeMacid[ k ] = (unsigned char)strtol(&CpeMacHoldingBuf[ k * 2 ], NULL, 16);
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG Parent Mac address = %0x\n", CpeMacid[ k ] ));
    }

    // assume 1 parent ONLY
    // Parent MAC
    avro_value_set_branch(&adrField, 1, &parent_optional);
    avro_value_get_by_name(&parent_optional, "mac_address", &parent_adrField, NULL);
    if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
    avro_value_set_branch(&parent_adrField, 1, &parent_optional);
    avro_value_set_fixed(&parent_optional, CpeMacid, 6);
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, parent mac_address\tType: %d\n", avro_value_get_type(&parent_optional)));
    if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

    // Parent cpe_type
    avro_value_set_branch(&adrField, 1, &parent_optional);
    avro_value_get_by_name(&parent_optional, "cpe_type", &parent_adrField, NULL);
    if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
    avro_value_set_branch(&parent_adrField, 1, &parent_optional);
    avro_value_set_string(&parent_optional, CPE_TYPE_GATEWAY_STRING);
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, parent cpe_type\tType: %d\n", avro_value_get_type(&parent_optional)));
    if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

    // no more parent, set NULL
    avro_value_set_branch(&adrField, 1, &parent_optional);
    avro_value_get_by_name(&parent_optional, "cpe_parent", &parent_adrField, NULL);
    avro_value_set_branch(&parent_adrField, 0, &parent_optional);
    avro_value_set_null(&parent_optional);
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, parent cpe_parent\tType: %d\n", avro_value_get_type(&parent_optional)));
    if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
    
  }



  //host_table_version block
  avro_value_get_by_name(&adr, "host_table_version", &adrField, NULL);
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
  avro_value_set_branch(&adrField, 1, &optional);
  avro_value_set_long(&optional, lmHosts.lastActivity);
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, host_table_version\tType: %d\n", avro_value_get_type(&optional)));
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

  //Data Field block

  avro_value_get_by_name(&adr, "data", &adrField, NULL);
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, NetworkDeviceStatusReports - data array\tType: %d\n", avro_value_get_type(&adrField)));
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

  //adrField now contains a reference to the AssociatedDeviceReportsArray
  //Device Report
  avro_value_t dr = {0,0};

  //Current Device Report Field
  avro_value_t drField = {0,0};

  while(ptr)
  {

    if( (!strcmp(ptr->parent, parent_mac) && (extender == TRUE)) || (extender == FALSE) )
    {

      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Current Link List Ptr = [0x%lx], numElements = %d\n", (ulong)ptr, numElements ));
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, \tDevice entry #: %d\n", i + 1));

      //Append a DeviceReport item to array
      avro_value_append(&adrField, &dr, NULL);
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, \tDevice Status Report\tType: %d\n", avro_value_get_type(&dr)));

      //data array block

      memset(CpeMacHoldingBuf, 0, sizeof CpeMacHoldingBuf);
      memset(CpeMacid, 0, sizeof CpeMacid);

      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Mac address from node list  = %s \n", ptr->device_mac ));

      for (k = 0; k < 6; k++ )
      {
        /* copy 2 bytes */
        CpeMacHoldingBuf[ k * 2 ] = ptr->device_mac[ k * 3 ];
        CpeMacHoldingBuf[ k * 2 + 1 ] = ptr->device_mac[ k * 3 + 1 ];
        CpeMacid[ k ] = (unsigned char)strtol(&CpeMacHoldingBuf[ k * 2 ], NULL, 16);
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Mac address = %0x\n", CpeMacid[ k ] ));
      }

      //device_mac - fixed 6 bytes
      avro_value_get_by_name(&dr, "device_id", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, device_id\tType: %d\n", avro_value_get_type(&drField)));
      avro_value_get_by_name(&drField, "mac_address", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_set_fixed(&optional, CpeMacid, 6);
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, \tmac_address\tType: %d\n", avro_value_get_type(&optional)));
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //device_type - string
      avro_value_get_by_name(&dr, "device_id", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, device_id\tType: %d\n", avro_value_get_type(&drField)));
      avro_value_get_by_name(&drField, "device_type", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_set_string(&optional, ptr->device_type);
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, \tdevice_type\tType: %d\n", avro_value_get_type(&optional)));
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //timestamp - long
      avro_value_get_by_name(&dr, "timestamp", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      int64_t tstamp_av = (int64_t) ptr->timestamp.tv_sec * 1000000 + (int64_t) ptr->timestamp.tv_usec;
      tstamp_av = tstamp_av/1000;
      avro_value_set_long(&optional, tstamp_av);
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, timestamp = ""%" PRId64 "\n", tstamp_av ));

      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, \ttimestamp\tType: %d\n", avro_value_get_type(&optional)));
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //interface_name - string
      avro_value_get_by_name(&dr, "interface_name", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      //avro_value_set_string(&optional, "  aa  ");
      avro_value_set_string(&optional, ptr->interface_name );
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, \tinterface_name\tType: %d\n", avro_value_get_type(&optional)));
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //status - enum
      avro_value_get_by_name(&dr, "status", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, status\tType: %d\n", avro_value_get_type(&optional)));
      if ( ptr->is_active )
          avro_value_set_enum(&optional, avro_schema_enum_get_by_name(avro_value_get_schema(&optional), "ONLINE"));
      else
          avro_value_set_enum(&optional, avro_schema_enum_get_by_name(avro_value_get_schema(&optional), "OFFLINE"));
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //hostname - string
      avro_value_get_by_name(&dr, "hostname", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_set_string(&optional, ptr->hostname);
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, \thostname\tType: %d\n", avro_value_get_type(&optional)));
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //ipaddress - array
      avro_value_get_by_name(&dr, "ip_addresses", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_append(&optional, &array, NULL);
      avro_value_set_string(&array, ptr->ipaddress);
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, \tipaddress\tType: %d\n", avro_value_get_type(&optional)));
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      i++;
    }

#if SIMULATION
    ptr = 0;
#else
    ptr = ptr->next; // next link list
#endif

    /* check for writer size, if buffer is almost full, skip trailing linklist */
    avro_value_sizeof(&adr, &AvroSerializedSize);
    OneAvroSerializedSize = ( OneAvroSerializedSize == 0 ) ? AvroSerializedSize : OneAvroSerializedSize;

    if ( ( WRITER_BUF_SIZE - AvroSerializedSize ) < OneAvroSerializedSize )
    {
      CcspLMLiteTrace(("RDK_LOG_ERROR, AVRO write buffer is almost full, size = %d func %s, exit!\n", (int)AvroSerializedSize, __FUNCTION__ ));
      break;
    }

  }

  //Thats the end of that
  avro_value_write(writer, &adr);

  avro_value_sizeof(&adr, &AvroSerializedSize);
  AvroSerializedSize += MAGIC_NUMBER_SIZE + SCHEMA_ID_LENGTH;
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Serialized writer size %d\n", (int)AvroSerializedSize));

  //Free up memory
  avro_value_decref(&adr);

  avro_writer_free(writer);
  //free(buffer);



/*  if ( consoleDebugEnable )
  {
    // b64 encoding 
    decodesize = b64_get_encoded_buffer_size( AvroSerializedSize );
    b64buffer = malloc(decodesize * sizeof(uint8_t));
    b64_encode( (uint8_t*)AvroSerializedBuf, AvroSerializedSize, b64buffer);

    fprintf( stderr, "\nAVro serialized data\n");
    for (k = 0; k < (int)AvroSerializedSize ; k++)
    {
      char buf[30];
      if ( ( k % 32 ) == 0 )
        fprintf( stderr, "\n");
      sprintf(buf, "%02X", (unsigned char)AvroSerializedBuf[k]);
      fprintf( stderr, "%c%c", buf[0], buf[1] );
    }

    fprintf( stderr, "\n\nB64 data\n");
    for (k = 0; k < (int)decodesize; k++)
    {
      if ( ( k % 32 ) == 0 )
        fprintf( stderr, "\n");
      fprintf( stderr, "%c", b64buffer[k]);
    }
    fprintf( stderr, "\n\n");
    free(b64buffer);
  }*/

  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Before ND WebPA SEND message call\n"));
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, serviceName: %s\n", serviceName));
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, dest: %s\n", dest));
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, trans_id: %s\n", trans_id));
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, contentType: %s\n", contentType));
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, AvroSerializedBuf: %s\n", AvroSerializedBuf));
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, AvroSerializedSize: %d\n", (int)AvroSerializedSize));
  // Send data from LMLite to webpa using CCSP bus interface
  sendWebpaMsg(serviceName, dest, trans_id, contentType, AvroSerializedBuf, AvroSerializedSize);

  CcspTraceWarning(("NetworkDevicesStatus report sent to Webpa, Destination=%s, Transaction-Id=%s  \n",dest,trans_id));
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, After ND WebPA SEND message call\n"));


  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : EXIT \n", __FUNCTION__ ));

#if SIMULATION
  exit(0);
#endif
}

void nds_avro_cleanup()
{
  if(ndsschemabuffer != NULL) {
  	free(ndsschemabuffer);
  	ndsschemabuffer=NULL;
  }
  if(iface != NULL){ 	
  	avro_value_iface_decref(iface);
	iface = NULL;
  }
  schema_file_parsed = FALSE;
}


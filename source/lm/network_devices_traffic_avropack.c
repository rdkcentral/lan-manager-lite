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
#include "network_devices_traffic_avropack.h"
#include "ccsp_lmliteLog_wrapper.h"

#ifdef MLT_ENABLED
#include "rpl_malloc.h"
#include "mlt_malloc.h"
#endif

#define MAGIC_NUMBER      0x85
#define MAGIC_NUMBER_SIZE 1
#define SCHEMA_ID_LENGTH  32
#define WRITER_BUF_SIZE   1024 * 30 // 30K

//      "schemaTypeUUID" : "5fc8321e-d8bf-45a7-8b3c-3dcdfd091092",
//      "schemaMD5Hash" : "1a73afad2380ee4730dacfcbf359222b",

uint8_t HASH_NDT[16] = {0x1a, 0x73, 0xaf, 0xad, 0x23, 0x80, 0xee, 0x47,
                        0x30, 0xda, 0xcf, 0xcb, 0xf3, 0x59, 0x22, 0x2b
                   };

uint8_t UUID_NDT[16] = {0x5f, 0xc8, 0x32, 0x1e, 0xd8, 0xbf, 0x45, 0xa7,
                        0x8b, 0x3c, 0x3d, 0xcd, 0xfd, 0x09, 0x10, 0x92
                   };


static char *macStr = NULL;
static char CpemacStr[ 32 ];
BOOL ndt_schema_file_parsed = FALSE;
char *ndtschemabuffer = NULL;
char *ndtschemaidbuffer = "5fc8321e-d8bf-45a7-8b3c-3dcdfd091092/1a73afad2380ee4730dacfcbf359222b";
static size_t AvroSerializedSize;
static size_t OneAvroSerializedSize;
static char AvroSerializedBuf[ WRITER_BUF_SIZE ];
static avro_value_iface_t  *iface = NULL;

// local data, load it with real data if necessary
char ReportSourceNDT[72] = "LMLite";
char CPE_TYPE_STRING_NDT[] = "Gateway";

#ifdef EXTENDER_CODE
char ParentCpeMacid[] = { 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33 };
int cpe_parent_exists = FALSE;
char PARENT_CPE_TYPE_STRING[] = "BBParent ExtenderBB";
#endif
// local data, load it with real data if necessary


#ifndef UTC_ENABLE
extern int getTimeOffsetFromUtc();
#endif

#ifdef WAN_FAILOVER_SUPPORTED
void set_ReportSourceNDT(char * value)
{
    /* CID 281036 Buffer not null terminated */
    snprintf(ReportSourceNDT, sizeof(ReportSourceNDT), "%s", value);
}

char * get_ReportSourceNDT(void)
{
     return ReportSourceNDT;
}
#endif

char* GetNDTrafficSchemaBuffer()
{
  return ndtschemabuffer;
}

int GetNDTrafficSchemaBufferSize()
{
int len = 0;
if(ndtschemabuffer)
	len = strlen(ndtschemabuffer);
  
return len;
}

char* GetNDTrafficSchemaIDBuffer()
{
  return ndtschemaidbuffer;
}

int GetNDTrafficSchemaIDBufferSize()
{
int len = 0;
if(ndtschemaidbuffer)
        len = strlen(ndtschemaidbuffer);

return len;
}

int NumberofElementsinNDTLinkedList(struct networkdevicetrafficdata* head)
{
  int numelements = 0;
  struct networkdevicetrafficdata* ptr  = head;
  while (ptr != NULL)
  {
    numelements++;
    ptr = ptr->next;
  }
  return numelements;
}


avro_writer_t prepare_writer()
{
  avro_writer_t writer;
  long lSize = 0;
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ENTER \n", __FUNCTION__ ));

  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Avro prepares to serialize data\n"));

  if ( ndt_schema_file_parsed == FALSE )
  {
    FILE *fp;

    /* open schema file */
    fp = fopen ( NETWORK_DEVICE_TRAFFIC_AVRO_FILENAME , "rb" );
    if ( !fp ) perror( NETWORK_DEVICE_TRAFFIC_AVRO_FILENAME " doesn't exist."), exit(1);

    /* seek through file and get file size*/
    fseek( fp , 0L , SEEK_END);
    lSize = ftell( fp );
    if (lSize < 0)
        fclose(fp), fputs("lSize is negative value", stderr), exit(1);

    /*back to the start of the file*/
    rewind( fp );

    /* allocate memory for entire content */
    ndtschemabuffer = calloc( 1, lSize + 1 );

    if ( !ndtschemabuffer ) fclose(fp), fputs("memory alloc fails", stderr), exit(1);

    /* copy the file into the buffer */
    if ( 1 != fread( ndtschemabuffer , lSize, 1 , fp) )
      fclose(fp), free(ndtschemabuffer), ndtschemabuffer=NULL,  fputs("entire read fails", stderr), exit(1);

    fclose(fp);
    /*CID:135642 String not null terminated*/
    ndtschemabuffer[lSize] = '\0';
    //schemas
    avro_schema_error_t  error = NULL;
 
    //Master report/datum
    avro_schema_t network_device_report_schema = NULL;
    avro_schema_from_json(ndtschemabuffer, strlen(ndtschemabuffer),
                        &network_device_report_schema, &error);

    //generate an avro class from our schema and get a pointer to the value interface
    iface = avro_generic_class_from_schema(network_device_report_schema);


    avro_schema_decref(network_device_report_schema);
    ndt_schema_file_parsed = TRUE; // parse schema file once only
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Read Avro schema file ONCE, lSize = %ld, pbuffer = 0x%lx.\n", lSize + 1, (ulong)ndtschemabuffer ));
  }
  else
  {
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Stored lSize = %ld, pbuffer = 0x%lx.\n", lSize + 1, (ulong)ndtschemabuffer ));
  }

  memset(&AvroSerializedBuf[0], 0, sizeof(AvroSerializedBuf));

  AvroSerializedBuf[0] = MAGIC_NUMBER; /* fill MAGIC number = Empty, i.e. no Schema ID */

  memcpy( &AvroSerializedBuf[ MAGIC_NUMBER_SIZE ], UUID_NDT, sizeof(UUID_NDT));

  memcpy( &AvroSerializedBuf[ MAGIC_NUMBER_SIZE + sizeof(UUID_NDT) ], HASH_NDT, sizeof(HASH_NDT));
  
  writer = avro_writer_memory( (char*)&AvroSerializedBuf[MAGIC_NUMBER_SIZE + SCHEMA_ID_LENGTH],
                               sizeof(AvroSerializedBuf) - MAGIC_NUMBER_SIZE - SCHEMA_ID_LENGTH );

  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : EXIT \n", __FUNCTION__ ));

  return writer;
}


/* function call from lmlite with parameters */
void network_devices_traffic_report(struct networkdevicetrafficdata *head, struct timeval *reset_timestamp)
{
  int i = 0, k = 0;
  int numElements = 0;
  struct networkdevicetrafficdata* ptr = head;
  avro_writer_t writer;
  char * serviceName = "lmlite";
  char * dest = "event:raw.kestrel.reports.NetworkDevicesTraffic";
  char * contentType = "avro/binary"; // contentType "application/json", "avro/binary"
  uuid_t ndt_transaction_id;
  char trans_id[37];

  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ENTER \n", __FUNCTION__ ));

  numElements = NumberofElementsinNDTLinkedList(head);

  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, numElements = %d\n", numElements ));

  OneAvroSerializedSize = 0;

  /* goes thru total number of elements in link list */
  writer = prepare_writer();


  //Reset out writer
  avro_writer_reset(writer);

  //Network Device Report
  avro_value_t  adr;
  avro_generic_value_new(iface, &adr);

  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, NetworkDeviceTrafficReport\tType: %d\n", avro_value_get_type(&adr)));

  avro_value_t  adrField = {0,0};

  //Optional value for unions, mac address is an union
  avro_value_t optional = {0,0};

  // timestamp - long
  avro_value_get_by_name(&adr, "header", &adrField, NULL);
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
  if (adrField.iface == NULL)
  {
     CcspTraceWarning(("adrField.iface is null"));
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
  uuid_generate_random(ndt_transaction_id); 
  uuid_unparse(ndt_transaction_id, trans_id);

  avro_value_get_by_name(&adr, "header", &adrField, NULL);
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
  avro_value_get_by_name(&adrField, "uuid", &adrField, NULL);
  avro_value_set_branch(&adrField, 1, &optional);
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
  avro_value_set_fixed(&optional, ndt_transaction_id, 16);
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, uuid\tType: %d\n", avro_value_get_type(&optional)));
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

  //source - string
  avro_value_get_by_name(&adr, "header", &adrField, NULL);
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
  avro_value_get_by_name(&adrField, "source", &adrField, NULL);
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
  avro_value_set_branch(&adrField, 1, &optional);
  avro_value_set_string(&optional, ReportSourceNDT);
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, source\tType: %d\n", avro_value_get_type(&optional)));
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

  //cpe_id block
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

  char CpeMacHoldingBuf[ 20 ] = {0};
  unsigned char CpeMacid[ 7 ] = {0};
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
  avro_value_set_string(&optional, CPE_TYPE_STRING_NDT);
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, cpe_type\tType: %d\n", avro_value_get_type(&optional)));
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

  // cpe_parent - Recurrsive CPEIdentifier block
  avro_value_get_by_name(&adr, "cpe_id", &adrField, NULL);
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
  avro_value_get_by_name(&adrField, "cpe_parent", &adrField, NULL);
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

#ifdef EXTENDER_CODE
  if ( cpe_parent_exists == FALSE )
#endif
  {    
      avro_value_set_branch(&adrField, 0, &optional);
      avro_value_set_null(&optional);
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, cpe_parent\tType: %d\n", avro_value_get_type(&optional)));
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
  }

#ifdef EXTENDER_CODE
  else
  {
      avro_value_t parent_optional, parent_adrField;

      // assume 1 parent ONLY
      // Parent MAC
      avro_value_set_branch(&adrField, 1, &parent_optional);
      avro_value_get_by_name(&parent_optional, "mac_address", &parent_adrField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&parent_adrField, 1, &parent_optional);
      avro_value_set_fixed(&parent_optional, ParentCpeMacid, 6);
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, parent mac_address\tType: %d\n", avro_value_get_type(&parent_optional)));
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      // Parent cpe_type
      avro_value_set_branch(&adrField, 1, &parent_optional);
      avro_value_get_by_name(&parent_optional, "cpe_type", &parent_adrField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&parent_adrField, 1, &parent_optional);
      avro_value_set_string(&parent_optional, PARENT_CPE_TYPE_STRING);
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
#endif

  //Last Traffic counter block

  avro_value_get_by_name(&adr, "last_traffic_counter_reset", &adrField, NULL);
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, NetworkDevicesTrafficReports - data array\tType: %d\n", avro_value_get_type(&adrField)));
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
  avro_value_set_branch(&adrField, 1, &optional);
  int64_t reset_tstamp_av = (int64_t) reset_timestamp->tv_sec * 1000000 + (int64_t) reset_timestamp->tv_usec;
  reset_tstamp_av = reset_tstamp_av/1000;
  avro_value_set_long(&optional, reset_tstamp_av);
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, reset_timestamp = ""%" PRId64 "\n", tstamp_av_main ));

  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, \tlast_traffic_counter_reset\tType: %d\n", avro_value_get_type(&optional)));
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

  //Data Field block

  avro_value_get_by_name(&adr, "data", &adrField, NULL);
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, NetworkDevicesTrafficReports - data array\tType: %d\n", avro_value_get_type(&adrField)));
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

  //adrField now contains a reference to the AssociatedDeviceReportsArray
  //Device Report
  avro_value_t dr = {0,0};

  //Current Device Report Field
  avro_value_t drField = {0,0};

  while(ptr)
  {
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Current Link List Ptr = [0x%lx], numElements = %d\n", (ulong)ptr, numElements ));
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, \tDevice entry #: %d\n", i + 1));
    
      //Append a DeviceReport item to array
      avro_value_append(&adrField, &dr, NULL);
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, \tDevice Traffic Report\tType: %d\n", avro_value_get_type(&dr)));

      //data array block

      memset(CpeMacHoldingBuf, 0, sizeof CpeMacHoldingBuf);
      memset(CpeMacid, 0, sizeof CpeMacid);
      
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

      //device_type - set NULL
      avro_value_get_by_name(&dr, "device_id", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, device_id\tType: %d\n", avro_value_get_type(&drField)));
      avro_value_get_by_name(&drField, "device_type", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_set_null(&optional);
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

      // external_bytes_up
      avro_value_get_by_name(&dr, "external_bytes_up", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, status\tType: %d\n", avro_value_get_type(&drField)));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_set_long(&optional, ptr->external_bytes_up);
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, \texternal_bytes_up\tType: %d\n", avro_value_get_type(&optional)));
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      // external_bytes_down
      avro_value_get_by_name(&dr, "external_bytes_down", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, status\tType: %d\n", avro_value_get_type(&drField)));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_set_long(&optional, ptr->external_bytes_down);
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, \texternal_bytes_down\tType: %d\n", avro_value_get_type(&optional)));      
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      i++;
    
    
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
      CcspLMLiteTrace(("RDK_LOG_ERROR, AVRO write buffer is almost full, size = %d func %s, exit!\n", (int)AvroSerializedSize, __FUNCTION__ ));      break;
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
  #ifdef WAN_FAILOVER_SUPPORTED
  CcspTraceWarning(("NetworkDevicesTraffic report sent to Webpa, Destination=%s, Transaction-Id=%s, source=%s\n",dest,trans_id,ReportSourceNDT));
  #else
  CcspTraceWarning(("NetworkDevicesTraffic report sent to Webpa, Destination=%s, Transaction-Id=%s  \n",dest,trans_id));
  #endif
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, After ND WebPA SEND message call\n"));


  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : EXIT \n", __FUNCTION__ ));

#if SIMULATION
  exit(0);
#endif
}


void ndt_avro_cleanup()
{
  if(ndtschemabuffer != NULL) {
        free(ndtschemabuffer); 
        ndtschemabuffer=NULL;
  } 
  if(iface != NULL){
        avro_value_iface_decref(iface);
        iface = NULL;
  }
  ndt_schema_file_parsed = FALSE;
}


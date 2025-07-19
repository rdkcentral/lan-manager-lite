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
#include "extender_associated_devices_avropack.h"
#include "webpa_interface.h"
#include "ccsp_lmliteLog_wrapper.h"

#define MAGIC_NUMBER      0x85
#define MAGIC_NUMBER_SIZE 1
#define SCHEMA_ID_LENGTH  32
#define WRITER_BUF_SIZE   1024 * 30 // 30K

// IDW_HASH - 7985cdc3a29f21c283fdcc0fcdcce550
// IDW_UUID - ec57a5b6-b167-4623-baff-399f063bd56a

uint8_t IDW_HASH[16] = {0x79, 0x85, 0xcd, 0xc3, 0xa2, 0x9f, 0x21, 0xc2,
                    0x83, 0xfd, 0xcc, 0x0f, 0xcd, 0xcc, 0xe5, 0x50
                   };

uint8_t IDW_UUID[16] = {0xec, 0x57, 0xa5, 0xb6, 0xb1, 0x67, 0x46, 0x23,
                    0xba, 0xff, 0x39, 0x9f, 0x06, 0x3b, 0xd5, 0x6a
                   };


// local data, load it with real data if necessary
char ReportSourceIDW[] = "lmlite";
char CPE_TYPE_EXTENDER_STRING_IDW[] = "Extender";
char CPE_TYPE_GATEWAY_STRING_IDW[] = "Gateway";
char DEVICE_TYPE_IDW[] = "WiFi";
char ParentCpeMacidIDW[] = { 0x77, 0x88, 0x99, 0x00, 0x11, 0x22 };
int cpe_parent_exists_idw = false;
// local data, load it with real data if necessary

/**** temperatory raw data ****/

#ifndef UTC_ENABLE
extern int getTimeOffsetFromUtc();
#endif

static char *macStr = NULL;
static char CpemacStr[ 32 ];
char *idw_buffer = NULL;
char *idw_schemaidbuffer = "ec57a5b6-b167-4623-baff-399f063bd56a/7985cdc3a29f21c283fdcc0fcdcce550";

BOOL schema_file_parsed_idw = FALSE;
size_t AvroSerializedSizeIDW;
size_t OneAvroSerializedSizeIDW;
char AvroSerializedBufIDW[ WRITER_BUF_SIZE ];
static avro_value_iface_t  *iface = NULL;
char* GetIDWSchemaBuffer()
{
  return idw_buffer;
}

int GetIDWSchemaBufferSize()
{
int len = 0;
if(idw_buffer)
  len = strlen(idw_buffer);
  
return len;
}

char* GetIDWSchemaIDBuffer()
{
  return idw_schemaidbuffer;
}

int GetIDWSchemaIDBufferSize()
{
int len = 0;
if(idw_schemaidbuffer)
        len = strlen(idw_schemaidbuffer);

return len;
}

int NumberofElementsinIDWLinkedList(struct associateddevicedata* head)
{
  int numelements = 0;
  struct associateddevicedata* ptr  = head;
  while (ptr != NULL)
  {
    numelements++;
    ptr = ptr->next;
  }
  return numelements;
}


ULONG NumberofDevicesinIDWLinkedList(struct associateddevicedata* head)
{
  ULONG numdevices = 0;
  struct associateddevicedata* ptr  = head;
  while (ptr != NULL)
  {
    numdevices = numdevices + ptr->numAssocDevices;
    ptr = ptr->next;
  }
  return numdevices;
}

avro_writer_t prepare_writer_idw()
{
  avro_writer_t writer;
  long lSize = 0;
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ENTER \n", __FUNCTION__ ));
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Avro prepares to serialize data\n"));

  if ( schema_file_parsed_idw == FALSE )
  {
    FILE *fp;

    /* open schema file */
    fp = fopen ( INTERFACE_DEVICES_WIFI_AVRO_FILENAME , "rb" );
    if ( !fp ) perror( INTERFACE_DEVICES_WIFI_AVRO_FILENAME " doesn't exist."), exit(1);

    /* seek through file and get file size*/
    fseek( fp , 0L , SEEK_END);
    lSize = ftell( fp );

    /*back to the start of the file*/
    rewind( fp );

    /* allocate memory for entire content */
    idw_buffer = calloc( 1, lSize + 1 );

    if ( !idw_buffer ) fclose(fp), fputs("memory alloc fails", stderr), exit(1);

    /* copy the file into the idw_buffer */
    if ( 1 != fread( idw_buffer , lSize, 1 , fp) )
      fclose(fp), free(idw_buffer), fputs("entire read fails", stderr), exit(1);

    fclose(fp);

    //schemas
    avro_schema_error_t  error = NULL;

    //Master report/datum
    avro_schema_t associated_device_report_schema = NULL;
    avro_schema_from_json(idw_buffer, strlen(idw_buffer),
                        &associated_device_report_schema, &error);

    //generate an avro class from our schema and get a pointer to the value interface
    iface = avro_generic_class_from_schema(associated_device_report_schema);
    avro_schema_decref(associated_device_report_schema);
    schema_file_parsed_idw = TRUE; // parse schema file once only
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Read Avro schema file ONCE, lSize = %ld, pbuffer = 0x%lx.\n", lSize + 1, (ulong)idw_buffer ));
  }
  else
  {
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Stored lSize = %ld, pbuffer = 0x%lx.\n", lSize + 1, (ulong)idw_buffer ));
  }

  memset(&AvroSerializedBufIDW[0], 0, sizeof(AvroSerializedBufIDW));

  AvroSerializedBufIDW[0] = MAGIC_NUMBER; /* fill MAGIC number = Empty, i.e. no Schema ID */

  memcpy( &AvroSerializedBufIDW[ MAGIC_NUMBER_SIZE ], IDW_UUID, sizeof(IDW_UUID));

  memcpy( &AvroSerializedBufIDW[ MAGIC_NUMBER_SIZE + sizeof(IDW_UUID) ], IDW_HASH, sizeof(IDW_HASH));

  writer = avro_writer_memory( (char*)&AvroSerializedBufIDW[MAGIC_NUMBER_SIZE + SCHEMA_ID_LENGTH],
                               sizeof(AvroSerializedBufIDW) - MAGIC_NUMBER_SIZE - SCHEMA_ID_LENGTH );

  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : EXIT \n", __FUNCTION__ ));

  return writer;
}


/* function call from harvester with parameters */
void extender_report_associateddevices(struct associateddevicedata *head, char* ServiceType, char* extender_mac)
{
  int i, j, k = 0;
  uint8_t* b64buffer =  NULL;
  size_t decodesize = 0;
  int numElements = 0;
  int numDevices = 0;
  wifi_associated_dev_t *ps = NULL;
  struct associateddevicedata* ptr = head;
  avro_writer_t writer;
  char * serviceName = "lmlite";
  char * dest = "event:raw.kestrel.reports.InterfaceDevicesWifi";
  char * contentType = "avro/binary"; // contentType "application/json", "avro/binary"
  uuid_t transaction_id;
  char trans_id[37];
  char CpeMacHoldingBuf[ 20 ] = {0};
  unsigned char CpeMacid[ 7 ] = {0};

  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : ENTER \n", __FUNCTION__ ));

  numElements = NumberofElementsinIDWLinkedList(head);
  numDevices = NumberofDevicesinIDWLinkedList(head);
  numDevices = numDevices; // get rid of warning if NO print

  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, numElements = %d\n", numElements ));

  OneAvroSerializedSizeIDW = 0;

  /* goes thru total number of elements in link list */
  writer = prepare_writer_idw();
 

  //Reset out writer
  avro_writer_reset(writer);

  //Associated Device Report
  avro_value_t  adr;
  avro_generic_value_new(iface, &adr);

  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, GatewayAssociatedDeviceReport\tType: %d\n", avro_value_get_type(&adr)));

  avro_value_t  adrField;

  //Optional value for unions, mac address is an union
  avro_value_t optional;

  // timestamp - long
  avro_value_get_by_name(&adr, "header", &adrField, NULL);
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
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
  
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, timestamp = %ld\n", tstamp_av_main ));
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
  unsigned char *ptxn = (unsigned char*)transaction_id;
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, uuid = 0x%02X, 0x%02X ... 0x%02X, 0x%02X\n", ptxn[0], ptxn[1], ptxn[14], ptxn[15] ));
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, uuid\tType: %d\n", avro_value_get_type(&optional)));
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

  //source - string
  avro_value_get_by_name(&adr, "header", &adrField, NULL);
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
  avro_value_get_by_name(&adrField, "source", &adrField, NULL);
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
  avro_value_set_branch(&adrField, 1, &optional);
  avro_value_set_string(&optional, ReportSourceIDW);
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, source = \"%s\"\n", ReportSourceIDW ));
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, source\tType: %d\n", avro_value_get_type(&optional)));
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

  //cpe_id block

  for (k = 0; k < 6; k++ )
  {
    /* copy 2 bytes */
    CpeMacHoldingBuf[ k * 2 ] = extender_mac[ k * 3 ];
    CpeMacHoldingBuf[ k * 2 + 1 ] = extender_mac[ k * 3 + 1 ];
    CpeMacid[ k ] = (unsigned char)strtol(&CpeMacHoldingBuf[ k * 2 ], NULL, 16);
    CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Extender Mac address = %0x\n", CpeMacid[ k ] ));
  }

  avro_value_get_by_name(&adr, "cpe_id", &adrField, NULL);
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
  avro_value_get_by_name(&adrField, "mac_address", &adrField, NULL);
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
  avro_value_set_branch(&adrField, 1, &optional);
  avro_value_set_fixed(&optional, CpeMacid, 6);
  unsigned char *pMac = (unsigned char*)CpeMacid;
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, mac_address = 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X\n", pMac[0], pMac[1], pMac[2], pMac[3], pMac[4], pMac[5] ));
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, mac_address\tType: %d\n", avro_value_get_type(&optional)));
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

  // cpe_type - string
  avro_value_get_by_name(&adr, "cpe_id", &adrField, NULL);
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
  avro_value_get_by_name(&adrField, "cpe_type", &adrField, NULL);
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
  avro_value_set_branch(&adrField, 1, &optional);
  avro_value_set_string(&optional, CPE_TYPE_EXTENDER_STRING_IDW);
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, cpe_type = \"%s\"\n", CPE_TYPE_EXTENDER_STRING_IDW ));
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, cpe_type\tType: %d\n", avro_value_get_type(&optional)));
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

  // cpe_parent - Recurrsive CPEIdentifier block
  avro_value_get_by_name(&adr, "cpe_id", &adrField, NULL);
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
  avro_value_get_by_name(&adrField, "cpe_parent", &adrField, NULL);
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

  avro_value_t parent_optional, parent_adrField;

  // assume 1 parent ONLY
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
  }

  // Parent MAC
  avro_value_set_branch(&adrField, 1, &parent_optional);
  avro_value_get_by_name(&parent_optional, "mac_address", &parent_adrField, NULL);
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
  avro_value_set_branch(&parent_adrField, 1, &parent_optional);
  avro_value_set_fixed(&parent_optional, CpeMacid, 6);
  pMac = (unsigned char*)CpeMacid;
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, parent mac = 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X\n", pMac[0], pMac[1], pMac[2], pMac[3], pMac[4], pMac[5] ));
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, parent mac_address\tType: %d\n", avro_value_get_type(&parent_optional)));
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

  // Parent cpe_type
  avro_value_set_branch(&adrField, 1, &parent_optional);
  avro_value_get_by_name(&parent_optional, "cpe_type", &parent_adrField, NULL);
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
  avro_value_set_branch(&parent_adrField, 1, &parent_optional);
  avro_value_set_string(&parent_optional, CPE_TYPE_GATEWAY_STRING_IDW);
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, parent cpe_type = \"%s\"\n", CPE_TYPE_GATEWAY_STRING_IDW ));
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, parent cpe_type\tType: %d\n", avro_value_get_type(&parent_optional)));
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

  // no more parent, set NULL
  avro_value_set_branch(&adrField, 1, &parent_optional);
  avro_value_get_by_name(&parent_optional, "cpe_parent", &parent_adrField, NULL);
  avro_value_set_branch(&parent_adrField, 0, &parent_optional);
  avro_value_set_null(&parent_optional);
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, parent cpe_parent = %s\n", "NULL" ));
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, parent cpe_parent\tType: %d\n", avro_value_get_type(&parent_optional)));
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

  //Data Field block

  avro_value_get_by_name(&adr, "data", &adrField, NULL);
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Associate Device Reports - data array\tType: %d\n", avro_value_get_type(&adrField)));
  if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

  //adrField now contains a reference to the Interface WiFi ReportsArray
  //Device Report
  avro_value_t dr;

  //Current Device Report Field
  avro_value_t drField;

  //interference sources
  avro_value_t interferenceSource;

  for (i = 0; i < numElements; i++)
  {
    for (j = 0, ps = ptr->devicedata; (j < ptr->numAssocDevices  && (!strcmp(ptr->parent, extender_mac))) ; j++, ps++)
    {

      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Current Link List Ptr = [0x%lx], numDevices = %d\n", (ulong)ptr, numDevices ));
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, \tDevice entry #: %d\n", j + 1));

      //Append a DeviceReport item to array
      avro_value_append(&adrField, &dr, NULL);
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, \tInterface Report\tType: %d\n", avro_value_get_type(&dr)));

      //data array block

      //device_mac - fixed 6 bytes
      avro_value_get_by_name(&dr, "device_id", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, device_id\tType: %d\n", avro_value_get_type(&drField)));
      avro_value_get_by_name(&drField, "mac_address", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_set_fixed(&optional, ps->cli_MACAddress, 6);
      pMac = (unsigned char*)ps->cli_MACAddress;
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, mac_address = 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X\n", pMac[0], pMac[1], pMac[2], pMac[3], pMac[4], pMac[5] ));
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, mac_address\tType: %d\n", avro_value_get_type(&optional)));
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //device_type - string
      avro_value_get_by_name(&dr, "device_id", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, device_id\tType: %d\n", avro_value_get_type(&drField)));
      avro_value_get_by_name(&drField, "device_type", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_set_string(&optional, DEVICE_TYPE_IDW);
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, device_type = \"%s\"\n", DEVICE_TYPE_IDW ));
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, device_type\tType: %d\n", avro_value_get_type(&optional)));
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //timestamp - long
      avro_value_get_by_name(&dr, "timestamp", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      int64_t tstamp_av = (int64_t) ptr->timestamp.tv_sec * 1000000 + (int64_t) ptr->timestamp.tv_usec;
      tstamp_av = tstamp_av/1000;
      avro_value_set_long(&optional, tstamp_av);
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, timestamp = ""%" PRId64 "\n", tstamp_av ));
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, timestamp\tType: %d\n", avro_value_get_type(&optional)));
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      // Service_type
      avro_value_get_by_name(&dr, "service_type", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Service_type\tType: %d\n", avro_value_get_type(&drField)));
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, service_type = \"%s\"\n", ServiceType ));
      avro_value_set_enum(&drField, avro_schema_enum_get_by_name(avro_value_get_schema(&drField), ServiceType));
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      /* RDKB-7592 : Extender connected device report should have correct interface_mac */
      memset(CpeMacHoldingBuf, 0, sizeof CpeMacHoldingBuf);
      memset(CpeMacid, 0, sizeof CpeMacid);

      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Mac address BSSID  = %s \n", ptr->bssid ));

      for (k = 0; k < 6; k++ )
      {
        /* copy 2 bytes */
        CpeMacHoldingBuf[ k * 2 ] = ptr->bssid[ k * 3 ];
        CpeMacHoldingBuf[ k * 2 + 1 ] = ptr->bssid[ k * 3 + 1 ];
        CpeMacid[ k ] = (unsigned char)strtol(&CpeMacHoldingBuf[ k * 2 ], NULL, 16);
        CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Interface Mac address = %0x\n", CpeMacid[ k ] ));
      }

      // interface_mac
      avro_value_get_by_name(&dr, "interface_mac", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, interface_mac\tType: %d\n", avro_value_get_type(&drField)));
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      /* RDKB-7592 : Extender connected device report should have correct interface_mac */
      avro_value_set_fixed(&drField, CpeMacid, 6);
      pMac = (unsigned char*)CpeMacid;
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, interface_mac = 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X\n", pMac[0], pMac[1], pMac[2], pMac[3], pMac[4], pMac[5] ));
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //interface parameters block

      // operating standard
      avro_value_get_by_name(&dr, "interface_parameters", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_get_by_name(&optional, "operating_standard", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, operating_standard\tType: %d\n", avro_value_get_type(&optional)));
      //Patch HAL values if necessary
      if ( strlen(ps->cli_OperatingStandard ) == 0 )      
      {
          CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, operating_standard = \"%s\"\n", "Not defined, set to NULL" ));
          avro_value_set_null(&optional);
      }
      else
      {
          CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, operating_standard = \"%s\"\n", ps->cli_OperatingStandard ));
          avro_value_set_enum(&optional, avro_schema_enum_get_by_name(avro_value_get_schema(&optional), ps->cli_OperatingStandard));
      }
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror())); 

      // operating channel bandwidth
      avro_value_get_by_name(&dr, "interface_parameters", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_get_by_name(&optional, "operating_channel_bandwidth", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, operating_channel_bandwidth\tType: %d\n", avro_value_get_type(&optional)));
      //Patch HAL values if necessary
      if ( strlen( ps->cli_OperatingChannelBandwidth) == 0 )
      {
          CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, operating_channel_bandwidth = \"%s\"\n", "Not defined, set to NULL" ));
          avro_value_set_null(&optional);
      }
      else
      {
          CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, operating_channel_bandwidth = \"%s\"\n", ps->cli_OperatingChannelBandwidth ));
          avro_value_set_enum(&optional, avro_schema_enum_get_by_name(avro_value_get_schema(&optional), ps->cli_OperatingChannelBandwidth));
      }
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      // frequency band
      avro_value_get_by_name(&dr, "interface_parameters", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_get_by_name(&optional, "frequency_band", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, frequency_band\tType: %d\n", avro_value_get_type(&optional)));
      //Patch HAL values if necessary
      if ( strcmp( ptr->radioOperatingFrequencyBand, "_2_4GHz" ) == 0 )
      {
          CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, frequency_band = \"%s\"\n", "2.4GHz, set to _2_4GHz" ));
          avro_value_set_enum(&optional, avro_schema_enum_get_by_name(avro_value_get_schema(&optional), "_2_4GHz" ));
      }
      else
      if ( strcmp( ptr->radioOperatingFrequencyBand, "_5GHz" ) == 0 )
      {
          CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, frequency_band = \"%s\"\n", "5GHz, set to _5GHz" ));
          avro_value_set_enum(&optional, avro_schema_enum_get_by_name(avro_value_get_schema(&optional), "_5GHz" ));
      }
      else
      {
          CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, frequency_band = \"%s\"\n", ptr->radioOperatingFrequencyBand ));
          avro_value_set_enum(&optional, avro_schema_enum_get_by_name(avro_value_get_schema(&optional), ptr->radioOperatingFrequencyBand));
      }
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      // channel #
      avro_value_get_by_name(&dr, "interface_parameters", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_get_by_name(&optional, "channel", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, channel = %ld\n", ptr->radioChannel));
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, channel\tType: %d\n", avro_value_get_type(&optional)));
      avro_value_set_int(&optional, ptr->radioChannel);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      // ssid
      avro_value_get_by_name(&dr, "interface_parameters", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_get_by_name(&optional, "ssid", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, ssid = \"%s\"\n", ptr->sSidName ));
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, ssid\tType: %d\n", avro_value_get_type(&optional)));
      avro_value_set_string(&optional, ptr->sSidName);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //interface metrics block

      //WIFI - authenticated
      avro_value_get_by_name(&dr, "interface_metrics", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_get_by_name(&optional, "authenticated", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, authenticated\tType: %d\n", avro_value_get_type(&optional)));
      if ( ps->cli_AuthenticationState )
      {
          CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, authenticated = TRUE\n"));
          avro_value_set_boolean(&optional, TRUE);
      }
      else
      {
          CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, authenticated = FALSE\n"));
          avro_value_set_boolean(&optional, FALSE);
      }
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //authentication failures
      avro_value_get_by_name(&dr, "interface_metrics", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_get_by_name(&optional, "authentication_failures", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, authentication_failures = %d\n", ps->cli_AuthenticationFailures));
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, authentication_failures\tType: %d\n", avro_value_get_type(&optional)));
      avro_value_set_int(&optional, ps->cli_AuthenticationFailures);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //data_frames_sent_ack
      avro_value_get_by_name(&dr, "interface_metrics", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_get_by_name(&optional, "data_frames_sent_ack", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, data_frames_sent_ack = %ld\n", ps->cli_DataFramesSentAck));
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, data_frames_sent_ack\tType: %d\n", avro_value_get_type(&optional)));
      avro_value_set_long(&optional, ps->cli_DataFramesSentAck);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //data_frames_sent_no_ack
      avro_value_get_by_name(&dr, "interface_metrics", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_get_by_name(&optional, "data_frames_sent_no_ack", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, data_frames_sent_no_ack = %ld\n", ps->cli_DataFramesSentNoAck));
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, data_frames_sent_no_ack\tType: %d\n", avro_value_get_type(&optional)));
      avro_value_set_long(&optional, ps->cli_DataFramesSentNoAck);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //disassociations
      avro_value_get_by_name(&dr, "interface_metrics", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_get_by_name(&optional, "disassociations", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, disassociations = %d\n", ps->cli_Disassociations));
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, disassociations\tType: %d\n", avro_value_get_type(&optional)));
      avro_value_set_int(&optional, ps->cli_Disassociations);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //interference_sources
      avro_value_get_by_name(&dr, "interface_metrics", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_get_by_name(&optional, "interference_sources", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, interference_sources\tType: %d\n", avro_value_get_type(&drField)));
      if (strstr( ps->cli_InterferenceSources, "MicrowaveOven") != NULL )
      {
          CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, interference_sources = \"%s\"\n", "set to MicrowaveOven" ));
          avro_value_append(&drField, &interferenceSource, NULL);
          avro_value_set_string(&interferenceSource,"MicrowaveOven");
      }
      if (strstr( ps->cli_InterferenceSources, "CordlessPhone") != NULL )
      {
          CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, interference_sources = \"%s\"\n", "set to CordlessPhone" ));
          avro_value_append(&drField, &interferenceSource, NULL);
          avro_value_set_string(&interferenceSource,"CordlessPhone");
      }
      if (strstr( ps->cli_InterferenceSources, "BluetoothDevices") != NULL )
      {
          CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, interference_sources = \"%s\"\n", "set to BluetoothDevices" ));
          avro_value_append(&drField, &interferenceSource, NULL);
          avro_value_set_string(&interferenceSource,"BluetoothDevices");
      }
      if (strstr( ps->cli_InterferenceSources, "FluorescentLights") != NULL )
      {
          CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, interference_sources = \"%s\"\n", "set to FluorescentLights" ));
          avro_value_append(&drField, &interferenceSource, NULL);
          avro_value_set_string(&interferenceSource,"FluorescentLights");
      }
      if (strstr( ps->cli_InterferenceSources, "ContinuousWaves") != NULL )
      {
          CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, interference_sources = \"%s\"\n", "set to ContinuousWaves" ));
          avro_value_append(&drField, &interferenceSource, NULL);
          avro_value_set_string(&interferenceSource,"ContinuousWaves");
      }
      avro_value_append(&drField, &interferenceSource, NULL);
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, interference_sources = \"%s\"\n", "also set to Others" ));
      avro_value_set_string(&interferenceSource,"Others");
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //rx_rate
      avro_value_get_by_name(&dr, "interface_metrics", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_get_by_name(&optional, "rx_rate", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, rx_rate = %d\n", ps->cli_LastDataDownlinkRate));
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, rx_rate\tType: %d\n", avro_value_get_type(&optional)));
      avro_value_set_float(&optional, (float)ps->cli_LastDataDownlinkRate);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //tx_rate
      avro_value_get_by_name(&dr, "interface_metrics", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_get_by_name(&optional, "tx_rate", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, tx_rate = %d\n", ps->cli_LastDataUplinkRate));
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, tx_rate\tType: %d\n", avro_value_get_type(&optional)));
      avro_value_set_float(&optional, (float)ps->cli_LastDataUplinkRate);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //retransmissions
      avro_value_get_by_name(&dr, "interface_metrics", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_get_by_name(&optional, "retransmissions", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, retransmissions = %d\n", ps->cli_Retransmissions));
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, retransmissions\tType: %d\n", avro_value_get_type(&optional)));
      avro_value_set_int(&optional, ps->cli_Retransmissions);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //signal_strength
      avro_value_get_by_name(&dr, "interface_metrics", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_get_by_name(&optional, "signal_strength", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);

      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, signal_strength = %d\n", ps->cli_SignalStrength));
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, signal_strength\tType: %d\n", avro_value_get_type(&optional)));
      avro_value_set_float(&optional, (float)ps->cli_SignalStrength);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //snr
      avro_value_get_by_name(&dr, "interface_metrics", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_get_by_name(&optional, "snr", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, snr = %d\n", ps->cli_SNR));
      CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, snr\tType: %d\n", avro_value_get_type(&optional)));
      avro_value_set_float(&optional, (float)ps->cli_SNR);
      if ( CHK_AVRO_ERR ) CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      // All done with schema, next entry if any

    }
    ptr = ptr->next; // next link list

    /* check for writer size, if buffer is almost full, skip trailing linklist */
    avro_value_sizeof(&adr, &AvroSerializedSizeIDW);
    OneAvroSerializedSizeIDW = ( OneAvroSerializedSizeIDW == 0 ) ? AvroSerializedSizeIDW : OneAvroSerializedSizeIDW;

    if ( ( WRITER_BUF_SIZE - AvroSerializedSizeIDW ) < OneAvroSerializedSizeIDW )
    {
      CcspLMLiteTrace(("RDK_LOG_ERROR, AVRO write buffer is almost full, size = %d func %s, exit!\n", (int)AvroSerializedSizeIDW, __FUNCTION__ ));
      break;
    }

  }
  //Thats the end of that
  avro_value_write(writer, &adr);

  avro_value_sizeof(&adr, &AvroSerializedSizeIDW);
  AvroSerializedSizeIDW += MAGIC_NUMBER_SIZE + SCHEMA_ID_LENGTH;
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Serialized writer size %d\n", (int)AvroSerializedSizeIDW));

  //Free up memory
  avro_value_decref(&adr);

  avro_writer_free(writer);
  //free(buffer);

  /* b64 encoding */
  decodesize = b64_get_encoded_buffer_size( AvroSerializedSizeIDW );
  b64buffer = malloc(decodesize * sizeof(uint8_t));
  b64_encode( (uint8_t*)AvroSerializedBufIDW, AvroSerializedSizeIDW, b64buffer);

/*  if ( consoleDebugEnable )
  {
    fprintf( stderr, "\nAVro serialized data\n");
    for (k = 0; k < (int)AvroSerializedSizeIDW ; k++)
    {
      char buf[30];
      if ( ( k % 32 ) == 0 )
        fprintf( stderr, "\n");
      sprintf(buf, "%02X", (unsigned char)AvroSerializedBufIDW[k]);
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
  }*/

  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, Before AD WebPA SEND message call\n"));
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, serviceName: %s\n", serviceName));
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, dest: %s\n", dest));
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, trans_id: %s\n", trans_id));
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, contentType: %s\n", contentType));
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, AvroSerializedBufIDW: %s\n", AvroSerializedBufIDW));
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, AvroSerializedSizeIDW: %d\n", (int)AvroSerializedSizeIDW));
  // Send data from LMLite to webpa using CCSP bus interface
  sendWebpaMsg(serviceName, dest, trans_id, contentType, AvroSerializedBufIDW, AvroSerializedSizeIDW);
  CcspTraceWarning(("ExtenderDevicesWifi report sent to Webpa, Destination=%s, Transaction-Id=%s  \n",dest,trans_id));
  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, After AD WebPA SEND message call\n"));

  free(b64buffer);

  CcspLMLiteConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : EXIT \n", __FUNCTION__ ));

#if SIMULATION
  exit(0);
#endif
}

void idw_avro_cleanup()
{
  if(idw_buffer != NULL) {
        free(idw_buffer); 
        idw_buffer=NULL;
  } 
  if(iface != NULL){
        avro_value_iface_decref(iface);
        iface = NULL;
  }
  schema_file_parsed_idw = FALSE;
}

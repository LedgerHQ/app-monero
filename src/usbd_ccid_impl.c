/**
  ******************************************************************************
  * @file    usbd_ccid_core.c
  * @author  MCD Application Team
  * @version V1.0.1
  * @date    31-January-2014
  * @brief   This file provides all the CCID core functions.
  *
  * @verbatim
  *      
  *          ===================================================================      
  *                                CCID Class  Description
  *          =================================================================== 
  *           This module manages the Specification for Integrated Circuit(s) 
  *             Cards Interface Revision 1.1
  *           This driver implements the following aspects of the specification:
  *             - Bulk Transfers 
  *      
  *  @endverbatim
  *
  ******************************************************************************
  * @attention
  *
  * <h2><center>&copy; COPYRIGHT 2014 STMicroelectronics</center></h2>
  *
  * Licensed under MCD-ST Liberty SW License Agreement V2, (the "License");
  * You may not use this file except in compliance with the License.
  * You may obtain a copy of the License at:
  *
  *        http://www.st.com/software_license_agreement_liberty_v2
  *
  * Unless required by applicable law or agreed to in writing, software 
  * distributed under the License is distributed on an "AS IS" BASIS, 
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  * See the License for the specific language governing permissions and
  * limitations under the License.
  *
  ******************************************************************************
  */ 

/* Includes ------------------------------------------------------------------*/
#include "usbd_ccid_core.h"

#ifdef HAVE_USB_CLASS_CCID

#define USBD_LANGID_STRING            0x409

#define USBD_VID                      0x2C97
#if TARGET_ID == 0x31000002 // blue
#define USBD_PID                      0x0000
static const uint8_t const USBD_PRODUCT_FS_STRING[] = {
  4*2+2,
  USB_DESC_TYPE_STRING,
  'B', 0,
  'l', 0,
  'u', 0,
  'e', 0,
};

#elif TARGET_ID == 0x31100002 // nano s
#define USBD_PID                      0x0001
static const uint8_t const USBD_PRODUCT_FS_STRING[] = {
  6*2+2,
  USB_DESC_TYPE_STRING,
  'N', 0,
  'a', 0,
  'n', 0,
  'o', 0,
  ' ', 0,
  'S', 0,
};
#elif TARGET_ID == 0x31200002 // aramis
#define USBD_PID                      0x0002
static const uint8_t const USBD_PRODUCT_FS_STRING[] = {
  6*2+2,
  USB_DESC_TYPE_STRING,
  'A', 0,
  'r', 0,
  'a', 0,
  'm', 0,
  'i', 0,
  's', 0,
};
#else
#error unknown TARGET_ID
#endif


/* USB Standard Device Descriptor */
static __ALIGN_BEGIN const uint8_t const USBD_DeviceQualifierDesc[] __ALIGN_END =
{
  USB_LEN_DEV_QUALIFIER_DESC,
  USB_DESC_TYPE_DEVICE_QUALIFIER,
  0x00,
  0x02,
  0x00,
  0x00,
  0x00,
  0x40,
  0x01,
  0x00,
};

/* USB Standard Device Descriptor */
static const uint8_t const USBD_LangIDDesc[]= 
{
  USB_LEN_LANGID_STR_DESC,         
  USB_DESC_TYPE_STRING,       
  LOBYTE(USBD_LANGID_STRING),
  HIBYTE(USBD_LANGID_STRING), 
};

static const uint8_t const USB_SERIAL_STRING[] =
{
  4*2+2,      
  USB_DESC_TYPE_STRING,
  '0', 0,
  '0', 0,
  '0', 0,
  '1', 0,
};

static const uint8_t const USBD_MANUFACTURER_STRING[] = {
  6*2+2,
  USB_DESC_TYPE_STRING,
  'L', 0,
  'e', 0,
  'd', 0,
  'g', 0,
  'e', 0,
  'r', 0,
};

#define USBD_INTERFACE_FS_STRING USBD_PRODUCT_FS_STRING
#define USBD_CONFIGURATION_FS_STRING USBD_PRODUCT_FS_STRING


/* USB Standard Device Descriptor */
static const uint8_t const USBD_DeviceDesc[]= {
  0x12,                       /* bLength */
  USB_DESC_TYPE_DEVICE,       /* bDescriptorType */
  0x00,                       /* bcdUSB */
  0x02,
  0x00,                       /* bDeviceClass */
  0x00,                       /* bDeviceSubClass */
  0x00,                       /* bDeviceProtocol */
  USB_MAX_EP0_SIZE,           /* bMaxPacketSize */
  LOBYTE(USBD_VID),           /* idVendor */
  HIBYTE(USBD_VID),           /* idVendor */
  LOBYTE(USBD_PID),           /* idVendor */
  HIBYTE(USBD_PID),           /* idVendor */
  0x00,                       /* bcdDevice rel. 2.00 */
  0x02,
  USBD_IDX_MFC_STR,           /* Index of manufacturer string */
  USBD_IDX_PRODUCT_STR,       /* Index of product string */
  USBD_IDX_SERIAL_STR,        /* Index of serial number string */
  USBD_MAX_NUM_CONFIGURATION  /* bNumConfigurations */
}; /* USB_DeviceDescriptor */


/* USB Mass storage device Configuration Descriptor */
/*   All Descriptors (Configuration, Interface, Endpoint, Class, Vendor */
#define USBD_OFFSET_CfgDesc_bPINSupport 70
const  uint8_t N_USBD_CfgDesc[] =
{
  
  0x09,   /* bLength: Configuration Descriptor size */
  USB_DESC_TYPE_CONFIGURATION,   /* bDescriptorType: Configuration */
  0x9+0x9+0x36+0x7+0x7+0x7,
  
  0x00,
  0x01,   /* bNumInterfaces: 1 interface */
  0x01,   /* bConfigurationValue: */
  0x04,   /* iConfiguration: */
  0x80,         /*bmAttributes: bus powered */
  0x32,   /* MaxPower 100 mA */
  
  /********************  CCID **** interface ********************/
  0x09,   /* bLength: Interface Descriptor size */
  0x04,   /* bDescriptorType: */
  0x00,   /* bInterfaceNumber: Number of Interface */
  0x00,   /* bAlternateSetting: Alternate setting */
  0x03,   /* bNumEndpoints: 3 endpoints used */
  0x0B,   /* bInterfaceClass: user's interface for CCID */
  0x00,   /* bInterfaceSubClass : */
  0x00,   /* nInterfaceProtocol : None */
  0x05,   /* iInterface: */

  /*******************  CCID class descriptor ********************/
  0x36,   /* bLength: CCID Descriptor size */
  0x21,   /* bDescriptorType: Functional Descriptor type. */
  0x10,   /* bcdCCID(LSB): CCID Class Spec release number (1.00) */
  0x01,   /* bcdCCID(MSB) */
  
  0x00,   /* bMaxSlotIndex :highest available slot on this device */
  0x03,   /* bVoltageSupport: bit Wise OR for 01h-5.0V 02h-3.0V
                                    04h 1.8V*/
  
  0x01,0x00,0x00,0x00,  /* dwProtocols: 0001h = Protocol T=0 */
  0x10,0x0E,0x00,0x00,  /* dwDefaultClock: 3.6Mhz = 3600kHz = 0x0E10, 
                             for 4 Mhz the value is (0x00000FA0) : 
                            This is used in ETU and waiting time calculations*/
  0x10,0x0E,0x00,0x00,  /* dwMaximumClock: Maximum supported ICC clock frequency 
                             in KHz. So, 3.6Mhz = 3600kHz = 0x0E10, 
                                           4 Mhz (0x00000FA0) : */
  0x00,     /* bNumClockSupported : no setting from PC 
                             If the value is 00h, the 
                            supported clock frequencies are assumed to be the 
                            default clock frequency defined by dwDefaultClock 
                            and the maximum clock frequency defined by 
                            dwMaximumClock */
  
  0xCD,0x25,0x00,0x00,  /* dwDataRate: Default ICC I/O data rate in bps
                            9677 bps = 0x25CD 
                            for example 10752 bps (0x00002A00) */
                             
  0xCD,0x25,0x00,0x00,  /* dwMaxDataRate: Maximum supported ICC I/O data 
                            rate in bps */
  0x00,                 /* bNumDataRatesSupported :
                         The number of data rates that are supported by the CCID
                         If the value is 00h, all data rates between the default 
                         data rate dwDataRate and the maximum data rate 
                         dwMaxDataRate are supported.
                         Dont support GET_CLOCK_FREQUENCIES
                        */     
  //46   
  0x00,0x00,0x00,0x00,   /* dwMaxIFSD: 0 (T=0 only)   */
  0x00,0x00,0x00,0x00,   /* dwSynchProtocols  */
  0x00,0x00,0x00,0x00,   /* dwMechanical: no special characteristics */
  
  0x38,0x00,EXCHANGE_LEVEL_FEATURE,0x00,   
                         /* dwFeatures: clk, baud rate, voltage : automatic */
                         /* 00000008h Automatic ICC voltage selection 
                         00000010h Automatic ICC clock frequency change
                         00000020h Automatic baud rate change according to 
                         active parameters provided by the Host or self 
                         determined 00000100h CCID can set 
                         ICC in clock stop mode      
                         
                         Only one of the following values may be present to 
                         select a level of exchange:
                         00010000h TPDU level exchanges with CCID
                         00020000h Short APDU level exchange with CCID
                         00040000h Short and Extended APDU level exchange 
                         If none of those values : character level of exchange*/
  #if 1
  0x0F,0x01,0x00,0x00,  /* dwMaxCCIDMessageLength: Maximum block size + header*/
                        /* 261 + 10   */
  #else
  0xF8,0x00,0x00,0x00,  /* dwMaxCCIDMessageLength: Maximum block size + header*/
                        /* EEh + 10   */
  #endif
  0x00,     /* bClassGetResponse*/
  0x00,     /* bClassEnvelope */
  0x00,0x00,    /* wLcdLayout : 0000h no LCD. */
  0x03,     /* bPINSupport : no PIN verif and modif  */                  //<= offset: 70
  0x01,     /* bMaxCCIDBusySlots  */

  //72
  /********************  CCID   Endpoints ********************/
  0x07,   /*Endpoint descriptor length = 7*/
  0x05,   /*Endpoint descriptor type */
  CCID_BULK_IN_EP,   /*Endpoint address (IN, address 1) */
  0x02,   /*Bulk endpoint type */
  LOBYTE(CCID_BULK_EPIN_SIZE),
  HIBYTE(CCID_BULK_EPIN_SIZE),
  0x00,   /*Polling interval in milliseconds */
  
  0x07,   /*Endpoint descriptor length = 7 */
  0x05,   /*Endpoint descriptor type */
  CCID_BULK_OUT_EP,   /*Endpoint address (OUT, address 1) */
  0x02,   /*Bulk endpoint type */
  LOBYTE(CCID_BULK_EPOUT_SIZE),
  HIBYTE(CCID_BULK_EPOUT_SIZE),
  0x00,   /*Polling interval in milliseconds*/
    
    
  0x07,   /*bLength: Endpoint Descriptor size*/
  0x05,   /*bDescriptorType:*/
  CCID_INTR_IN_EP,    /*bEndpointAddress: Endpoint Address (IN)*/
  0x03,   /* bmAttributes: Interrupt endpoint */
  LOBYTE(CCID_INTR_EPIN_SIZE),
  HIBYTE(CCID_INTR_EPIN_SIZE),
  0x18    /*Polling interval in milliseconds */
};



static uint8_t  *USBD_GetCfgDesc_impl (uint16_t *length)
{
  *length = sizeof (N_USBD_CfgDesc);
  return (uint8_t*)(N_USBD_CfgDesc);
}

/**
  * @brief  Returns the device descriptor. 
  * @param  speed: Current device speed
  * @param  length: Pointer to data length variable
  * @retval Pointer to descriptor buffer
  */
static uint8_t *USBD_DeviceDescriptor(USBD_SpeedTypeDef speed, uint16_t *length)
{
  UNUSED(speed);
  *length = sizeof(USBD_DeviceDesc);
  return (uint8_t*)USBD_DeviceDesc;
}

/**
  * @brief  Returns the LangID string descriptor.        
  * @param  speed: Current device speed
  * @param  length: Pointer to data length variable
  * @retval Pointer to descriptor buffer
  */
static uint8_t *USBD_LangIDStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length)
{
  UNUSED(speed);
  *length = sizeof(USBD_LangIDDesc);  
  return (uint8_t*)USBD_LangIDDesc;
}

/**
  * @brief  Returns the product string descriptor. 
  * @param  speed: Current device speed
  * @param  length: Pointer to data length variable
  * @retval Pointer to descriptor buffer
  */
static uint8_t *USBD_ProductStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length)
{
  UNUSED(speed);
  *length = sizeof(USBD_PRODUCT_FS_STRING);
  return (uint8_t*)USBD_PRODUCT_FS_STRING;
}

/**
  * @brief  Returns the manufacturer string descriptor. 
  * @param  speed: Current device speed
  * @param  length: Pointer to data length variable
  * @retval Pointer to descriptor buffer
  */
static uint8_t *USBD_ManufacturerStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length)
{
  UNUSED(speed);
  *length = sizeof(USBD_MANUFACTURER_STRING);
  return (uint8_t*)USBD_MANUFACTURER_STRING;
}

/**
  * @brief  Returns the serial number string descriptor.        
  * @param  speed: Current device speed
  * @param  length: Pointer to data length variable
  * @retval Pointer to descriptor buffer
  */
static uint8_t *USBD_SerialStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length)
{
  UNUSED(speed);
  *length = sizeof(USB_SERIAL_STRING);
  return (uint8_t*)USB_SERIAL_STRING;
}

/**
  * @brief  Returns the configuration string descriptor.    
  * @param  speed: Current device speed
  * @param  length: Pointer to data length variable
  * @retval Pointer to descriptor buffer
  */
static uint8_t *USBD_ConfigStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length)
{
  UNUSED(speed);
  *length = sizeof(USBD_CONFIGURATION_FS_STRING);
  return (uint8_t*)USBD_CONFIGURATION_FS_STRING;
}

/**
  * @brief  Returns the interface string descriptor.        
  * @param  speed: Current device speed
  * @param  length: Pointer to data length variable
  * @retval Pointer to descriptor buffer
  */
static uint8_t *USBD_InterfaceStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length)
{
  UNUSED(speed);
  *length = sizeof(USBD_INTERFACE_FS_STRING);
  return (uint8_t*)USBD_INTERFACE_FS_STRING;
}

/**
* @brief  DeviceQualifierDescriptor 
*         return Device Qualifier descriptor
* @param  length : pointer data length
* @retval pointer to descriptor buffer
*/
static uint8_t  *USBD_GetDeviceQualifierDesc_impl (uint16_t *length)
{
  *length = sizeof (USBD_DeviceQualifierDesc);
  return (uint8_t*)USBD_DeviceQualifierDesc;
}


uint8_t SC_AnswerToReset (uint8_t voltage, uint8_t* atr_buffer) {
  // return the atr length
  atr_buffer[0] = 0x3B;
  atr_buffer[1] = 0;
  return 2;
}


// note: how core lib usb calls the hid class
static const USBD_DescriptorsTypeDef const CCID_Desc = {
  USBD_DeviceDescriptor,
  USBD_LangIDStrDescriptor, 
  USBD_ManufacturerStrDescriptor,
  USBD_ProductStrDescriptor,
  USBD_SerialStrDescriptor,
  USBD_ConfigStrDescriptor,
  USBD_InterfaceStrDescriptor,
  NULL,
};

static const USBD_ClassTypeDef USBD_CCID = 
{
  USBD_CCID_Init,
  USBD_CCID_DeInit,
  USBD_CCID_Setup,
  NULL, /*EP0_TxSent*/  
  NULL, /*EP0_RxReady*/
  USBD_CCID_DataIn,
  USBD_CCID_DataOut,
  NULL, /*SOF */      
  NULL, /*ISOIn*/
  NULL, /*ISOOut*/
  USBD_GetCfgDesc_impl,
  USBD_GetCfgDesc_impl,
  USBD_GetCfgDesc_impl,
  USBD_GetDeviceQualifierDesc_impl,
};


void USBD_CCID_activate_pinpad(int enabled) {
  unsigned char e;
  e = enabled?3:0;
  nvm_write(((char*)PIC(N_USBD_CfgDesc))+USBD_OFFSET_CfgDesc_bPINSupport, &e,1);
}

void USB_CCID_power(unsigned char enabled) {
  os_memset(&USBD_Device, 0, sizeof(USBD_Device));

  if (enabled) {
    os_memset(&USBD_Device, 0, sizeof(USBD_Device));
    /* Init Device Library */
    USBD_Init(&USBD_Device, (USBD_DescriptorsTypeDef*)&CCID_Desc, 0);
    
    /* Register the HID class */
    USBD_RegisterClass(&USBD_Device, (USBD_ClassTypeDef*)&USBD_CCID);

    /* Start Device Process */
    USBD_Start(&USBD_Device);
  }
  else {
    USBD_DeInit(&USBD_Device);
  }
}

#endif // HAVE_USB_CLASS_CCID

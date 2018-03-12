/* Copyright 2017 Cedric Mesnil <cslashm@gmail.com>, Ledger SAS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */



#include "os.h"
#include "cx.h"
#include "monero_types.h"
#include "monero_api.h"
#include "monero_vars.h"

#include "monero_ux_msg.h"
#include "os_io_seproxyhal.h"
#include "usbd_ccid_impl.h"
#include "string.h"
#include "glyphs.h"


/* ----------------------------------------------------------------------- */
/* ---                        NanoS  UI layout                         --- */
/* ----------------------------------------------------------------------- */

const ux_menu_entry_t ui_menu_reset[] ;
void ui_menu_reset_action(unsigned int value);

const ux_menu_entry_t ui_menu_settings[] ;

const ux_menu_entry_t ui_menu_main[];
void ui_menu_main_display(unsigned int value) ;
const bagl_element_t* ui_menu_main_preprocessor(const ux_menu_entry_t* entry, bagl_element_t* element);



/* ------------------------------- Helpers  UX ------------------------------- */
void ui_CCID_reset(void) {
  io_usb_ccid_set_card_inserted(0);
  io_usb_ccid_set_card_inserted(1);
}
/*
void ui_info(const char* msg1, const char* msg2, const void *menu_display, unsigned int value) {
  os_memset(&G_monero_vstate.ui_dogsays[0], 0, sizeof(ux_menu_entry_t));
  G_monero_vstate.ui_dogsays[0].callback = menu_display;
  G_monero_vstate.ui_dogsays[0].userid   = value;
  G_monero_vstate.ui_dogsays[0].line1    = msg1;
  G_monero_vstate.ui_dogsays[0].line2    = msg2;

  os_memset(&G_monero_vstate.ui_dogsays[1],0, sizeof(ux_menu_entry_t));
  UX_MENU_DISPLAY(0, G_monero_vstate.ui_dogsays, NULL);
};
*/
/* ----------------------------- FEE VALIDATION ----------------------------- */
#define ACCEPT  0xACCE
#define REJECT  ~ACCEPT

void ui_menu_fee_validation_action(unsigned int value);

const ux_menu_entry_t ui_menu_fee_validation[] = {
  {NULL,  NULL,                           1,      NULL, " Fee",     "?xmr?",  0, 0},
  {NULL,  ui_menu_fee_validation_action,  REJECT, NULL,  "Reject",  "TX",     0, 0},
  {NULL,  ui_menu_fee_validation_action,  ACCEPT, NULL,  "Accept",  "TX",     0, 0},
  UX_MENU_END
};

const bagl_element_t* ui_menu_fee_validation_preprocessor(const ux_menu_entry_t* entry, bagl_element_t* element) {

  /* --- Amount --- */
  if (entry == &ui_menu_fee_validation[0]) {
    if(element->component.userid==0x22) {      
      element->text = G_monero_vstate.ux_amount;
    }
  }
  return element;
}

void ui_menu_fee_validation_action(unsigned int value) {
  unsigned short sw;
  if (value == ACCEPT) {
    sw = 0x9000;
  } else {
   sw = SW_SECURITY_STATUS_NOT_SATISFIED;
    monero_abort_tx();
  }
  monero_io_insert_u16(sw);  
  monero_io_do(IO_RETURN_AFTER_TX);
  ui_menu_main_display(0);
}

void ui_menu_fee_validation_display(unsigned int value) {
  UX_MENU_DISPLAY(0, ui_menu_fee_validation, ui_menu_fee_validation_preprocessor);
}

/* ----------------------------- USER DEST/AMOUNT VALIDATION ----------------------------- */
void ui_menu_validation_action(unsigned int value);

const ux_menu_entry_t ui_menu_validation[] = {
  {NULL,  NULL,                       1,      NULL, " Amount",       "?xmr?",      0, 0},
  {NULL,  NULL,                       3,      NULL,  "Destination",  "?dest.1?",   0, 0},
  {NULL,  NULL,                       4,      NULL,  "?dest.2?",     "?dest.2?",   0, 0},
  {NULL,  NULL,                       5,      NULL,  "?dest.3?",     "?dest.3?",   0, 0},
  {NULL,  NULL,                       6,      NULL,  "?dest.4?",     "?dest.4?",   0, 0},
  {NULL,  NULL,                       7,      NULL,  "?dest.5?",     "?dest.5?",   0, 0},
  {NULL,  ui_menu_validation_action,  REJECT, NULL,  "Reject",       "TX",         0, 0},
  {NULL,  ui_menu_validation_action,  ACCEPT, NULL,  "Accept",       "TX",         0, 0},
  UX_MENU_END
};

const bagl_element_t* ui_menu_validation_preprocessor(const ux_menu_entry_t* entry, bagl_element_t* element) {

  /* --- Amount --- */
  if (entry == &ui_menu_validation[0]) {
    if(element->component.userid==0x22) {      
      element->text = G_monero_vstate.ux_amount;
    }
  }
  #if 0
  /* --- Fees --- */
  if (entry == &ui_menu_validation[1]) {
    if(element->component.userid==0x22) {      
      element->text = G_monero_vstate.ux_fees;
    }
  }
#endif

   /* --- Destination --- */
  if (entry == &ui_menu_validation[1]) {
    if(element->component.userid==0x22) {     
      os_memset(G_monero_vstate.ux_menu, 0, sizeof(G_monero_vstate.ux_menu)) ;
      os_memmove(G_monero_vstate.ux_menu, G_monero_vstate.ux_address+11*0, 11);
      element->text = G_monero_vstate.ux_menu;
    }
  }
  if (entry == &ui_menu_validation[2]) {
    os_memset(G_monero_vstate.ux_menu, 0, sizeof(G_monero_vstate.ux_menu)) ;
    if(element->component.userid==0x21) {     
      os_memmove(G_monero_vstate.ux_menu, G_monero_vstate.ux_address+11*1, 11);      
    }
    if(element->component.userid==0x22) {     
      os_memmove(G_monero_vstate.ux_menu, G_monero_vstate.ux_address+11*2, 11);
    }
    element->text = G_monero_vstate.ux_menu;
  }
  if (entry == &ui_menu_validation[3]) {
    os_memset(G_monero_vstate.ux_menu, 0, sizeof(G_monero_vstate.ux_menu)) ;
    if(element->component.userid==0x21) {     
      os_memmove(G_monero_vstate.ux_menu, G_monero_vstate.ux_address+11*3, 11);      
    }
    if(element->component.userid==0x22) {     
      os_memmove(G_monero_vstate.ux_menu, G_monero_vstate.ux_address+11*4, 11);
    }
    element->text = G_monero_vstate.ux_menu;
  }
  if (entry == &ui_menu_validation[4]) {
    os_memset(G_monero_vstate.ux_menu, 0, sizeof(G_monero_vstate.ux_menu)) ;
    if(element->component.userid==0x21) {     
      os_memmove(G_monero_vstate.ux_menu, G_monero_vstate.ux_address+11*5, 11);      
    }
    if(element->component.userid==0x22) {     
      os_memmove(G_monero_vstate.ux_menu, G_monero_vstate.ux_address+11*6, 11);
    }
    element->text = G_monero_vstate.ux_menu;
  }
  if (entry == &ui_menu_validation[5]) {
    os_memset(G_monero_vstate.ux_menu, 0, sizeof(G_monero_vstate.ux_menu)) ;
    if(element->component.userid==0x21) {     
      os_memmove(G_monero_vstate.ux_menu, G_monero_vstate.ux_address+11*7, 11);      
    }
    if(element->component.userid==0x22) {     
      os_memmove(G_monero_vstate.ux_menu, G_monero_vstate.ux_address+11*8, 7);
    }
    element->text = G_monero_vstate.ux_menu;
  }

  return element;
}

void ui_menu_validation_display(unsigned int value) {
  UX_MENU_DISPLAY(0, ui_menu_validation, ui_menu_validation_preprocessor);
}

void ui_menu_validation_action(unsigned int value) {
  unsigned short sw;
  if (value == ACCEPT) {
    sw = 0x9000;
  } else {
   sw = SW_SECURITY_STATUS_NOT_SATISFIED;
    monero_abort_tx();
  }
  monero_io_insert_u16(sw);  
  monero_io_do(IO_RETURN_AFTER_TX);
  ui_menu_main_display(0);
}

/* -------------------------------- NETWORK UX --------------------------------- */
void ui_menu_network_action(unsigned int value);
const ux_menu_entry_t ui_menu_network[] = {
  {NULL,   NULL,                   0,        NULL, "It will reset", "the device!", 0, 0},
  {NULL,   ui_menu_main_display,   0,                                      &C_badge_back, "Abort",         NULL,          61, 40},
  {NULL,   ui_menu_network_action, TESTNET,  NULL, "Test Network",  NULL,          0, 0},
  {NULL,   ui_menu_network_action, STAGENET, NULL, "Stage Network", NULL,          0, 0},
  {NULL,   ui_menu_network_action, MAINNET,  NULL, "Main Network",  NULL,          0, 0},
  UX_MENU_END
};

void ui_menu_network_action(unsigned int value) {
  monero_install(value);
  monero_init();
  ui_menu_main_display(0);
}

/* -------------------------------- RESET UX --------------------------------- */

const ux_menu_entry_t ui_menu_reset[] = {
  {NULL,   NULL,                 0, NULL,          "Really Reset ?", NULL, 0, 0},
  {NULL,   ui_menu_main_display, 0, &C_badge_back, "No",         NULL, 61, 40},
  {NULL,   ui_menu_reset_action, 0, NULL,          "Yes",           NULL, 0, 0},
  UX_MENU_END
};

void ui_menu_reset_action(unsigned int value) {
  unsigned char magic[4];
  magic[0] = 0; magic[1] = 0; magic[2] = 0; magic[3] = 0;
  monero_nvm_write(N_monero_pstate->magic, magic, 4);
  monero_init();
  ui_menu_main_display(0);
}
/* ------------------------------- SETTINGS UX ------------------------------- */

const ux_menu_entry_t ui_menu_settings[] = {
  {ui_menu_network,             NULL,     0, NULL,          "Change Network",        NULL, 0, 0},
  {ui_menu_reset,               NULL,     0, NULL,          "Reset",        NULL, 0, 0},
  {NULL,        ui_menu_main_display,     2, &C_badge_back, "Back",         NULL, 61, 40},
  UX_MENU_END
};



/* --------------------------------- INFO UX --------------------------------- */


#define STR(x)  #x
#define XSTR(x) STR(x)

const ux_menu_entry_t ui_menu_info[] = {
  {NULL,  NULL,                 -1, NULL,          "Monero",                   NULL, 0, 0},
  {NULL,  NULL,                 -1, NULL,          "(c) Ledger SAS",           NULL, 0, 0},
  {NULL,  NULL,                 -1, NULL,          "Spec  " XSTR(SPEC_VERSION),NULL, 0, 0},
  {NULL,  NULL,                 -1, NULL,          "App  " XSTR(MONERO_VERSION),  NULL, 0, 0},
  {NULL,  ui_menu_main_display,  3, &C_badge_back, "Back",                     NULL, 61, 40},
  UX_MENU_END
};

#undef STR
#undef XSTR

/* --------------------------------- MAIN UX --------------------------------- */

const ux_menu_entry_t ui_menu_main[] = {
  {NULL,                       NULL,  0, NULL,              "",            NULL, 0, 0},
  {ui_menu_settings,           NULL,  0, NULL,              "Settings",    NULL, 0, 0},
  {ui_menu_info,               NULL,  0, NULL,              "About",       NULL, 0, 0},
  {NULL,              os_sched_exit,  0, &C_icon_dashboard, "Quit app" ,   NULL, 50, 29},
  UX_MENU_END
};
extern const  uint8_t N_USBD_CfgDesc[];
const bagl_element_t* ui_menu_main_preprocessor(const ux_menu_entry_t* entry, bagl_element_t* element) {
  if (entry == &ui_menu_main[0]) {
    if(element->component.userid==0x20) {      
    
      os_memset(G_monero_vstate.ux_menu, '#', sizeof(G_monero_vstate.ux_menu));
      snprintf(G_monero_vstate.ux_menu,  sizeof(G_monero_vstate.ux_menu), "< Monero: %s >", N_monero_pstate->public_address);
      
      element->component.stroke = 10; // 1 second stop in each way
      element->component.icon_id = 48; // roundtrip speed in pixel/s
      element->text = G_monero_vstate.ux_menu;
      UX_CALLBACK_SET_INTERVAL(bagl_label_roundtrip_duration_ms(element, 7));
    }
  }
  return element;
}
void ui_menu_main_display(unsigned int value) {
   UX_MENU_DISPLAY(value, ui_menu_main, ui_menu_main_preprocessor);
}

void ui_init(void) {
 ui_menu_main_display(0);
 // setup the first screen changing
  UX_CALLBACK_SET_INTERVAL(1000);
}

void io_seproxyhal_display(const bagl_element_t *element) {
  io_seproxyhal_display_default((bagl_element_t *)element);
}

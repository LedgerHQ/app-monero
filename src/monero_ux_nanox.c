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



#ifdef UI_NANO_X

#include "os.h"
#include "cx.h"
#include "monero_types.h"
#include "monero_api.h"
#include "monero_vars.h"

#include "monero_ux_msg.h"
#include "os_io_seproxyhal.h"
#include "string.h"
#include "glyphs.h"

/* ----------------------------------------------------------------------- */
/* ---                        NanoS  UI layout                         --- */
/* ----------------------------------------------------------------------- */


#define ACCEPT  0xACCE
#define REJECT  ~ACCEPT


void ui_menu_main_display(unsigned int value);

/* -------------------------------------- 25 WORDS --------------------------------------- */
void ui_menu_words_display(unsigned int value);
void ui_menu_words_clear(unsigned int value);
void ui_menu_words_back(unsigned int value);


UX_FLOW_DEF_NOCB(
  ux_menu_words_1_step,
  bnnn_paging,
  {
    .title = "Electrum Seed",
    .text = G_monero_vstate.ux_words,
  });


UX_FLOW_DEF_VALID(
  ux_menu_words_2_step,
  bn,
  ui_menu_words_clear(0),
  {
    "CLEAR WORDS",
    "(Do not wipe the wallet)"
  });

UX_FLOW_DEF_VALID(
  ux_menu_words_3_step,
  pb,
  ui_menu_words_back(0),
  {
    &C_icon_back,
    "back"
  });

UX_DEF(
  ux_flow_words,
  &ux_menu_words_1_step,
  &ux_menu_words_2_step,
  &ux_menu_words_3_step
  );

void ui_menu_words_clear(unsigned int value) {
  monero_clear_words();
  ui_menu_main_display(0);
}

void ui_menu_words_back(unsigned int value) {
  ui_menu_main_display(1);
}

static int ui_strncpy(char *dest, const char *src, int n) {
  int i;
  i = 0;
  while(i < n) {
    if (!src[i]) {
      break;
    }
    dest[i] = src[i];
    i++;
  }
  return i;
}

void ui_menu_words_display(unsigned int value) {
  int offset = 0;
  os_memset(G_monero_vstate.ux_words, 0, sizeof(G_monero_vstate.ux_words));
  for (int i = 0; i < 25; i++) {
    offset += ui_strncpy(G_monero_vstate.ux_words+offset, (char*)N_monero_pstate->words[i], 20);
    G_monero_vstate.ux_words[offset] = ' ';
    offset++;
  }
  ux_flow_init(0, ux_flow_words, NULL);
}

/* ----------------------------- FEE VALIDATION ----------------------------- */

void ui_menu_amount_validation_action(unsigned int value);

UX_FLOW_DEF_NOCB(
  ux_menu_validation_fee_1_step,
  bn,
  {
    "Fee",
    G_monero_vstate.ux_amount,
  });

UX_FLOW_DEF_NOCB(
  ux_menu_validation_change_1_step,
  bn,
  {
    "Change",
    G_monero_vstate.ux_amount,
  });

UX_FLOW_DEF_VALID(
  ux_menu_validation_cf_2_step,
  pb,
  ui_menu_amount_validation_action(ACCEPT),
  {
    &C_icon_validate_14,
    "Accept",
  });

UX_FLOW_DEF_VALID(
  ux_menu_validation_cf_3_step,
  pb,
  ui_menu_amount_validation_action(REJECT),
  {
    &C_icon_crossmark,
    "Reject",
  });

UX_DEF(ux_flow_fee,
  &ux_menu_validation_fee_1_step,
  &ux_menu_validation_cf_2_step,
  &ux_menu_validation_cf_3_step
  );

UX_DEF(ux_flow_change,
  &ux_menu_validation_change_1_step,
  &ux_menu_validation_cf_2_step,
  &ux_menu_validation_cf_3_step
  );


void ui_menu_amount_validation_action(unsigned int value) {
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
  ux_flow_init(0, ux_flow_fee, NULL);
}

void ui_menu_change_validation_display(unsigned int value) {
  ux_flow_init(0, ux_flow_change, NULL);
}

/* ----------------------------- USER DEST/AMOUNT VALIDATION ----------------------------- */
void ui_menu_validation_action(unsigned int value);

UX_FLOW_DEF_NOCB(
  ux_menu_validation_1_step,
  bn,
  {
    "Amout",
    G_monero_vstate.ux_amount
  });

UX_FLOW_DEF_NOCB(
  ux_menu_validation_2_step,
  bnnn_paging,
  {
    "Destination",
    G_monero_vstate.ux_address
  });

UX_FLOW_DEF_VALID(
  ux_menu_validation_3_step,
  pb,
  ui_menu_validation_action(ACCEPT),
  {
    &C_icon_validate_14,
    "Accept"
  });

UX_FLOW_DEF_VALID(
  ux_menu_validation_4_step,
  pb,
  ui_menu_validation_action(REJECT),
  {
    &C_icon_crossmark,
    "Reject"
  });

UX_DEF(ux_flow_validation,
  &ux_menu_validation_1_step,
  &ux_menu_validation_2_step,
  &ux_menu_validation_3_step,
  &ux_menu_validation_4_step
  );

void ui_menu_validation_display(unsigned int value) {
  ux_flow_init(0, ux_flow_validation, NULL);
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

/* -------------------------------- EXPORT VIEW KEY UX --------------------------------- */
unsigned int ui_menu_export_viewkey_action(unsigned int value);

UX_FLOW_DEF_NOCB(
  ux_menu_export_viewkey_1_step,
  nn,
  {
    "Export",
    "View Key"
  });

UX_FLOW_DEF_VALID(
  ux_menu_export_viewkey_2_step,
  pb,
  ui_menu_export_viewkey_action(ACCEPT),
  {
    &C_icon_validate_14,
    "Accept"
  });

UX_FLOW_DEF_VALID(
  ux_menu_export_viewkey_3_step,
  pb,
  ui_menu_export_viewkey_action(REJECT),
  {
    &C_icon_crossmark,
    "Reject"
  });

UX_DEF(ux_flow_export_viewkey,
  &ux_menu_export_viewkey_1_step,
  &ux_menu_export_viewkey_2_step,
  &ux_menu_export_viewkey_3_step
  );

void ui_export_viewkey_display(unsigned int value) {
  ux_flow_init(0, ux_flow_export_viewkey,NULL);
}


unsigned int ui_menu_export_viewkey_action(unsigned int value) {
  unsigned int sw;
  unsigned char x[32];

  monero_io_discard(0);
  os_memset(x,0,32);
  sw = 0x9000;

  if (value == ACCEPT) {
    monero_io_insert(G_monero_vstate.a, 32);
  } else {
    monero_io_insert(x, 32);
  }
  monero_io_insert_u16(sw);
  monero_io_do(IO_RETURN_AFTER_TX);
  ui_menu_main_display(0);
  return 0;
}

/* -------------------------------- NETWORK UX --------------------------------- */

void ui_menu_network_action(unsigned int value);

UX_FLOW_DEF_NOCB(
  ux_menu_network_1_step,
  nnn,
  {
    "Changing network",
    "will reset the",
    "application"
  });


UX_FLOW_DEF_VALID(
  ux_menu_network_2_step,
  nnbnn,
  ui_menu_network_action(MAINNET),
  {
    "", "",
    "Main Network",
    "", ""
  });

UX_FLOW_DEF_VALID(
  ux_menu_network_3_step,
  nnbnn,
  ui_menu_network_action(TESTNET),
  {
    "", "",
    "Test Network"
    "", ""
  });

UX_FLOW_DEF_VALID(
  ux_menu_network_4_step,
  nnbnn,
  ui_menu_network_action(STAGENET),
  {
    "", "",
    "Stage Network"
    "", ""
  });


UX_FLOW_DEF_VALID(
  ux_menu_network_5_step,
  pb,
  ui_menu_network_action(0),
  {
    &C_icon_back,
    "Abort"
  });

UX_DEF(ux_flow_network,
  &ux_menu_network_1_step,
  &ux_menu_network_2_step,
  &ux_menu_network_3_step,
  &ux_menu_network_4_step,
  &ux_menu_network_5_step
  );

void ui_menu_network_action(unsigned int value) {
  if (value) {
    monero_install(value);
    monero_init();
  }
  ui_menu_main_display(0);
}

void ui_menu_network_display(unsigned int value) {
   ux_flow_init(0, ux_flow_network, 0);
}

/* -------------------------------- RESET UX --------------------------------- */
void ui_menu_reset_display(unsigned int value);
void ui_menu_reset_action(unsigned int value);

UX_FLOW_DEF_NOCB(
  ux_menu_reset_1_step,
  nnn,
  {
    "",
    "Really Reset?",
    ""
  });

UX_FLOW_DEF_VALID(
  ux_menu_reset_2_step,
  pb,
  ui_menu_reset_action(REJECT),
  {
    &C_icon_crossmark,
    "No",
  });


UX_FLOW_DEF_VALID(
  ux_menu_reset_3_step,
  pb,
  ui_menu_reset_action(ACCEPT),
  {
    &C_icon_validate_14,
    "Yes",
  });

UX_DEF(ux_flow_reset,
  &ux_menu_reset_1_step,
  &ux_menu_reset_2_step,
  &ux_menu_reset_3_step
  );

void ui_menu_reset_display(unsigned int value) {
   ux_flow_init(0, ux_flow_reset, 0);
}

void ui_menu_reset_action(unsigned int value) {
  if (value == ACCEPT) {
    unsigned char magic[4];
    magic[0] = 0; magic[1] = 0; magic[2] = 0; magic[3] = 0;
    monero_nvm_write((void*)N_monero_pstate->magic, magic, 4);
    monero_init();
  }
  ui_menu_main_display(0);
}
/* ------------------------------- SETTINGS UX ------------------------------- */

UX_FLOW_DEF_VALID(
  ux_menu_settings_1_step,
  nnbnn,
  ui_menu_network_display(0),
  {
    "", ""
    "Change Network",
    "", ""
  });

UX_FLOW_DEF_VALID(
  ux_menu_settings_2_step,
  nnbnn,
  ui_menu_words_display(0),
  {
    "", ""
    "Show 25 words",
    "", ""
  });

UX_FLOW_DEF_VALID(
  ux_menu_settings_3_step,
  nnbnn,
  ui_menu_reset_display(0),
  {
    "", ""
    "Reset",
    "", ""
  });

UX_FLOW_DEF_VALID(
  ux_menu_settings_4_step,
  pb,
  ui_menu_main_display(0),
  {
    &C_icon_back,
    "Back",
  });


UX_DEF(ux_flow_settings,
  &ux_menu_settings_1_step,
  &ux_menu_settings_2_step,
  &ux_menu_settings_3_step,
  &ux_menu_settings_4_step
  );

void ui_menu_settings_display(unsigned int value) {
  ux_flow_init(0, ux_flow_settings, NULL);
}

/* --------------------------------- INFO UX --------------------------------- */
#define STR(x)  #x
#define XSTR(x) STR(x)

UX_FLOW_DEF_NOCB(
  ux_menu_info_1_step,
  bnnn,
  {
    "Monero",
    "(c) Ledger SAS",
    "Spec  " XSTR(SPEC_VERSION),
    "App  " XSTR(MONERO_VERSION),
  });

UX_FLOW_DEF_VALID(
  ux_menu_info_2_step,
  pb,
  ui_menu_main_display(0),
  {
    &C_icon_back,
    "Back",
  });



UX_DEF(ux_flow_info,
  &ux_menu_info_1_step,
  &ux_menu_info_2_step
  );


void ui_menu_info_display(unsigned int value) {
  ux_flow_init(0, ux_flow_info, NULL);
}

#undef STR
#undef XSTR

/* ---------------------------- PUBLIC ADDRESS UX ---------------------------- */

UX_FLOW_DEF_NOCB(
  ux_menu_pubaddr_1_step,
  bnnn_paging,
  {
    .title = "XMR",
    .text = G_monero_vstate.ux_wallet_public_address
  });

UX_FLOW_DEF_VALID(
  ux_menu_pubaddr_2_step,
  pb,
  ui_menu_main_display(0),
  {
    &C_icon_back,
    "Back"
  });

UX_DEF(ux_flow_pubaddr,
  &ux_menu_pubaddr_1_step,
  &ux_menu_pubaddr_2_step
  );

void ui_menu_pubaddr_display(unsigned int value) {
  ux_flow_init(0, ux_flow_pubaddr, NULL);
}


/* --------------------------------- MAIN UX --------------------------------- */

UX_FLOW_DEF_VALID(
  ux_menu_main_1_step,
  pbb,
  ui_menu_pubaddr_display(0),
  {
    &C_icon_monero,
    "XMR",
    G_monero_vstate.ux_wallet_public_short_address
  });

UX_FLOW_DEF_VALID(
  ux_menu_main_2_step,
  pb,
  ui_menu_settings_display(0),
  {
    &C_icon_coggle,
    "Settings"
  });

UX_FLOW_DEF_VALID(
  ux_menu_main_3_step,
  pb,
  ui_menu_info_display(0),
  {
    &C_icon_certificate,
    "About"
  });

UX_FLOW_DEF_VALID(
  ux_menu_main_4_step,
  pb,
  os_sched_exit(0),
  {
    &C_icon_dashboard_x,
    "Quit app"
  });


UX_DEF(ux_flow_main,
  &ux_menu_main_1_step,
  &ux_menu_main_2_step,
  &ux_menu_main_3_step,
  &ux_menu_main_4_step);

void ui_menu_main_display(unsigned int value) {
      // reserve a display stack slot if none yet
    if(G_ux.stack_count == 0) {
        ux_stack_push();
    }
     ux_flow_init(0, ux_flow_main, NULL);
}
/* --- INIT --- */

void ui_init(void) {
 ui_menu_main_display(0);
}

void io_seproxyhal_display(const bagl_element_t *element) {
  io_seproxyhal_display_default((bagl_element_t *)element);
}

#endif

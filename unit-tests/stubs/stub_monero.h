#pragma once

/* Point the app's network id at one network. Also zeroes both globals, so call
 * it from setUp(). */
void stub_set_network(unsigned char network_id);

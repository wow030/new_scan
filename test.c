#include <wchar.h>
#include <iostream>
#include <stdlib.h>
#include <errno.h>
#include <curses.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <stack>
#include <vector>
#include <sstream>
#include <cstring>
#include "sha256.h"
#include "hmac-sha1.h"
#include <openssl/hmac.h>
#include <cmath>
#include <iomanip>
#include <pthread.h>

using namespace std;

pthread_mutex_t lock;
bool if_first_packet_received = false;
int total_len_in_scan = 0;
bool* count_bit;
int packet_num = 0;
vector<uint8_t> uint8_t_vector;
uint8_t mac_to_middle[6];

struct hci_request ble_hci_request(uint16_t ocf, int clen, void * status, void * cparam)
{
	struct hci_request rq;
	memset(&rq, 0, sizeof(rq));
	rq.ogf = OGF_LE_CTL;
	rq.ocf = ocf;
	rq.cparam = cparam;
	rq.clen = clen;
	rq.rparam = status;
	rq.rlen = 1;
	return rq;
}

bool if_count_bit_full ( bool* count_bit, int len ) {
	int count = 0;

	for ( int i = 0; i < len; ++i ) {
		if ( count_bit[i] == true )
			count++;
		if ( count == (len + 1) )
			return true;
	}

	return false;

}

void* scan( void* arg )
{
	pthread_mutex_lock(&lock);
	int ret, status;

	// Get HCI device.

	const int device = hci_open_dev(hci_get_route(NULL));
	if ( device < 0 ) { 
		perror("Failed to open HCI device.");

	}

	// Set BLE scan parameters.
	
	le_set_scan_parameters_cp scan_params_cp;
	memset(&scan_params_cp, 0, sizeof(scan_params_cp));
	scan_params_cp.type 			= 0x00; 
	scan_params_cp.interval 		= htobs(0x0010);
	scan_params_cp.window 			= htobs(0x0010);
	scan_params_cp.own_bdaddr_type 	= 0x00; // Public Device Address (default).
	scan_params_cp.filter 			= 0x00; // Accept all.

	struct hci_request scan_params_rq = ble_hci_request(OCF_LE_SET_SCAN_PARAMETERS, LE_SET_SCAN_PARAMETERS_CP_SIZE, &status, &scan_params_cp);
	
	ret = hci_send_req(device, &scan_params_rq, 1000);
	if ( ret < 0 ) {
		hci_close_dev(device);
		perror("Failed to set scan parameters data.");

	}

	// Set BLE events report mask.

	le_set_event_mask_cp event_mask_cp;
	memset(&event_mask_cp, 0, sizeof(le_set_event_mask_cp));
	int i = 0;
	for ( i = 0 ; i < 8 ; i++ ) event_mask_cp.mask[i] = 0xFF;

	struct hci_request set_mask_rq = ble_hci_request(OCF_LE_SET_EVENT_MASK, LE_SET_EVENT_MASK_CP_SIZE, &status, &event_mask_cp);
	ret = hci_send_req(device, &set_mask_rq, 1000);
	if ( ret < 0 ) {
		hci_close_dev(device);
		perror("Failed to set event mask.");

	}

	// Enable scanning.

	le_set_scan_enable_cp scan_cp;
	memset(&scan_cp, 0, sizeof(scan_cp));
	scan_cp.enable 		= 0x01;	// Enable flag.
	scan_cp.filter_dup 	= 0x00; // Filtering disabled.

	struct hci_request enable_adv_rq = ble_hci_request(OCF_LE_SET_SCAN_ENABLE, LE_SET_SCAN_ENABLE_CP_SIZE, &status, &scan_cp);

	ret = hci_send_req(device, &enable_adv_rq, 1000);
	if ( ret < 0 ) {
		hci_close_dev(device);
		perror("Failed to enable scan.");

	}

	// Get Results.

	struct hci_filter nf;
	hci_filter_clear(&nf);
	hci_filter_set_ptype(HCI_EVENT_PKT, &nf);
	hci_filter_set_event(EVT_LE_META_EVENT, &nf);
	if ( setsockopt(device, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0 ) {
		hci_close_dev(device);
		perror("Could not set socket options\n");

	}

	printf( "------thread %d------\n", (int)arg );

	uint8_t buf[HCI_MAX_EVENT_SIZE];
	evt_le_meta_event * meta_event;
	le_advertising_info * info;
	int len;
	
	memset(&buf,0,sizeof(buf));
	len = read(device, buf, sizeof(buf));
	
	for ( i = 0; i < 50; ++i ) {
		printf( "%02x ", buf[i] );
	}
	
	printf("\n");
	// Disable scanning.
	
	while ( buf[19] != 0xB8 || buf[20] != 0x27 || buf[21] != 0xEB || buf[22] != 0xFC || buf[23] != 0x24 || buf[24] != 0x91 ) {
		
		if ( if_count_bit_full(count_bit, packet_num) == false ) {
			if (if_first_packet_received == false) {
				if ( buf[19] == 0xB8 && buf[20] == 0x27 && buf[21] == 0xEB && buf[22] == 0xFC && buf[23] == 0x24 
					&& buf[24] == 0x91 && buf[31] == 0x00 ) {
					total_len_in_scan = (int)buf[26];
					count_bit = new bool[total_len_in_scan];
					
					if (total_len_in_scan <= 18) {
						packet_num = 1;   
					}
					else {
						packet_num = 1 + ceil((float)(total_len_in_scan - 18)/19);
					}
					
					if ((int)buf[25]-48+1 == packet_num) {
						int begin_count = 27;
						int index_count = 0;
						while (index_count < total_len_in_scan) {
							uint8_t_vector.at(index_count) = buf[begin_count++];
							++index_count;
						}
					}
					else {
						int begin_count = 27;
						int index_count = 0;
						while ( index_count < 18  ) {
							uint8_t_vector.at(index_count) = buf[begin_count++];
							++index_count;
						}
					}
					
					count_bit[(int)buf[25] - 48] = true;
					if_first_packet_received = true;
				}	
			}
			else if ( buf[19] == 0xB8 && buf[20] == 0x27 && buf[21] == 0xEB && buf[22] == 0xFC && buf[23] == 0x24 
				&& buf[24] == 0x91 && if_first_packet_received == true ) {
				if ((int)buf[25] - 48 + 1 == packet_num) {
					cout << "get in" << endl;
					int begin_count = 26;
					int index_count = 0;
					int index_in_vector = 18 + ((int)buf[25] - 48 - 1)*19;
					while (index_in_vector < total_len_in_scan) {
						cout << index_in_vector << endl;
						uint8_t_vector.at(index_in_vector) = buf[begin_count];
						++begin_count;
						++index_in_vector;
					}
				}
				else {
					int begin_count = 26;
					int index_count = 0;

					int index_in_vector = 18 + ((int)buf[25]-48 - 1)*19;

					for ( int p = 0; p < 50; p++ ) {
						printf("%d > %c~\n",p,buf[p]);
					}

					while (index_count < 19) {
						uint8_t_vector.at(index_in_vector) = buf[begin_count];
						index_count++;
						begin_count++;
						++index_in_vector;

					}
				}
				count_bit[(int)buf[25] -48] = true;
			}
			
			memset(&buf,0,sizeof(buf));
			len = read(device, buf, sizeof(buf));
		} // if count_bit_full == false
		else {
			printf("count bit full.....\n");
		}
	}
	
	
	memset(&scan_cp, 0, sizeof(scan_cp));
	scan_cp.enable = 0x00;	// Disable flag.

	struct hci_request disable_adv_rq = ble_hci_request(OCF_LE_SET_SCAN_ENABLE, LE_SET_SCAN_ENABLE_CP_SIZE, &status, &scan_cp);
	ret = hci_send_req(device, &disable_adv_rq, 1000);
	if ( ret < 0 ) {
		hci_close_dev(device);
		perror("Failed to disable scan.");

	}

	hci_close_dev(device);
	pthread_mutex_unlock(&lock);
	pthread_exit(NULL);

}

void* advertise( void* arg ) {
	

}

int main()
{

	pthread_t my_thread[10];
	
    if (pthread_mutex_init(&lock, NULL) != 0)
    {
        printf("\n mutex init failed\n");
        return 1;
    }
	
	long id;
	for(id = 0; id < 10; id++) {
			int ret =  pthread_create(&my_thread[id], NULL, &scan, (void*)id);
			
			if(ret != 0) {
					printf("Error: pthread_create() failed\n");
					exit(EXIT_FAILURE);
			}
	}
	
	
	pthread_exit(NULL);
	return 0;
}

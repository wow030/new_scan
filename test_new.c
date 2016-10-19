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
bool if_send = false;
int packet_num = 0;
vector<uint8_t> uint8_t_vector;
vector<uint8_t> uint8_t_scan_vector;

uint8_t mac_to_middle[6];

le_set_advertising_data_cp ble_hci_params_for_set_adv_data(char * name)
{
	int name_len = strlen(name);

	le_set_advertising_data_cp adv_data_cp;
	memset(&adv_data_cp, 0, sizeof(adv_data_cp));

	// Build simple advertisement data bundle according to:
	// - ​"Core Specification Supplement (CSS) v5" 
	// ( https://www.bluetooth.org/en-us/specification/adopted-specifications )

	adv_data_cp.data[0] = 0x02; // Length.
	adv_data_cp.data[1] = 0x01; // Flags field.
	adv_data_cp.data[2] = 0x01; // LE Limited Discoverable Flag set

	adv_data_cp.data[3] = name_len + 1; // Length.
	adv_data_cp.data[4] = 0x09; // Name field.
	memcpy(adv_data_cp.data + 5, name, name_len);

	adv_data_cp.length = 5 + strlen(name);

	return adv_data_cp;
}

string hmacHex(string key, string msg)
{
    unsigned char hash[32];

    HMAC_CTX hmac;
    HMAC_CTX_init(&hmac);
    HMAC_Init_ex(&hmac, &key[0], key.length(), EVP_sha256(), NULL);
    HMAC_Update(&hmac, (unsigned char*)&msg[0], msg.length());
    unsigned int len = 32;
    HMAC_Final(&hmac, hash, &len);
    HMAC_CTX_cleanup(&hmac);

    std::stringstream ss;
    ss << hex << setfill('0');
    for (int i = 0; i < len; i++)
    {   
        ss << hex << setw(2)  << (unsigned int)hash[i];
    }

    return (ss.str());
}

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
		if ( count == len )
			return true;
	}

	return false;

}

void* scan( void* );

void* advertise();

int main()
{

	pthread_t my_thread[15];
	
    if (pthread_mutex_init(&lock, NULL) != 0)
    {
        printf("\n mutex init failed\n");
        return 1;
    }
	
	long id;
	for(id = 0; id < 15; id++) {
			int ret;
			//ret = pthread_create(&my_thread[id], NULL, &advertise,(void *)id);

			ret =  pthread_create(&my_thread[id], NULL, &scan, (void*)id);
			if(ret != 0) {
					printf("Error: pthread_create() failed\n");
					exit(EXIT_FAILURE);
			}
	}
	
	

	pthread_exit(NULL);
	return 0;
}

void* advertise() {

	printf("create advertise thread.......\n");
	while (1) {
		if ( if_count_bit_full(count_bit, packet_num) == true ) {
			printf("advertise .......\n");
			string input_string;
			for ( int j = 0; j < uint8_t_vector.size(); j++ ) {
				input_string += (char)uint8_t_vector.at(j);
				printf( "%d > %c\n",j ,uint8_t_vector.at(j) );
			}
			
			uint8_t LN1[4] = { 0x43,0x59,0x43,0x55 };
			input_string[input_string.size() - 1] = (char)(input_string[input_string.size() - 1] | LN1[3]);
			input_string[input_string.size() - 2] = (char)(input_string[input_string.size() - 2] | LN1[2]);
			input_string[input_string.size() - 3] = (char)(input_string[input_string.size() - 3] | LN1[1]);
			input_string[input_string.size() - 4] = (char)(input_string[input_string.size() - 4] | LN1[0]);
			
			uint8_t kn1[] = "ABCD";
			vector<uint8_t> mVector(input_string.begin(),input_string.end());
			uint8_t *p = &mVector[0];
			string sha1256 = hmacHex( "ABCD",input_string );
			string sha1256_32;
			for ( int i = 0; i < 32; ++i ) {
			sha1256_32 += ( sha1256[i*2] << 4 ) | ( sha1256[i*2 + 1] ); 
			}
			
			//printf("sha1256_output = %s\n",sha1256);

			int ret, status;
			
			cout << "======start to advertise======" << endl;
			// Get HCI device.

			const int device = hci_open_dev(hci_get_route(NULL));
			if ( device < 0 ) { 
				perror("Failed to open HC device.");

			}

			// Set BLE advertisement parameters.
			
			le_set_advertising_parameters_cp adv_params_cp;
			memset(&adv_params_cp, 0, sizeof(adv_params_cp));
			adv_params_cp.min_interval = htobs(0x0800);
			adv_params_cp.max_interval = htobs(0x0800);
			adv_params_cp.chan_map = 7;
			
			struct hci_request adv_params_rq = ble_hci_request(
				OCF_LE_SET_ADVERTISING_PARAMETERS,
				LE_SET_ADVERTISING_PARAMETERS_CP_SIZE, &status, &adv_params_cp);
			
			ret = hci_send_req(device, &adv_params_rq, 1000);
			if ( ret < 0 ) {
				hci_close_dev(device);
				perror("Failed to set advertisement parameters data.");

			}

			// Set BLE advertisement data.	
			int packet_count = 0;
			int sequence = 0;
			char* input_char;

			while ( packet_count < sha1256_32.size() ){
				string sub_input;
				if ( packet_count == 0 ) {
					stringstream ss;
					int i = 0;
					int index = 0;
					uint8_t mac[6] = {0xB8,0x27,0xEB,0xAB,0xBA,0x26};
					for ( i = 0; i< 6; ++i )
						sub_input += (char)mac[i];
					ss << sequence;
					sub_input += ss.str();
					stringstream ss_1;
					char len_p;
					cout << "length = " << sha1256_32.size();
					len_p = sha1256_32.size();
					cout << "len_p:" << len_p << endl;
					sub_input += len_p;
					if ( sha1256_32.size() >= 18 ) {
						sub_input += sha1256_32.substr(0,18);
						packet_count += 18;
					} 
					else {
						sub_input += sha1256_32.substr(0,sha1256_32.size());
						packet_count += sha1256_32.size();
					}

					cout << sub_input << endl;
				
				}
				else {
					int i = 0;
					uint8_t mac[] = {0xB8, 0x27, 0xEB, 0xAB, 0xBA, 0x26};
					for ( i = 0; i< 6; ++i ) {
						sub_input += (char)mac[i];
					}

					stringstream ss;
					ss << sequence;
					sub_input+=ss.str();
					if ( sha1256_32.size() - packet_count < 19 ) {
						sub_input += sha1256_32.substr( packet_count );
						packet_count += sha1256_32.size();
					}
					else {
						sub_input += sha1256_32.substr( packet_count, 19 );
						packet_count += 19;
					}
			
					cout << sub_input << endl;
				}

				input_char = new char[sub_input.size() + 1];
				memcpy( input_char, sub_input.c_str(), sub_input.size() + 1 );
				cout << "input_char : " << input_char << endl;
				le_set_advertising_data_cp adv_data_cp = ble_hci_params_for_set_adv_data(input_char);
			
				struct hci_request adv_data_rq = ble_hci_request(
					OCF_LE_SET_ADVERTISING_DATA,
					LE_SET_ADVERTISING_DATA_CP_SIZE, &status, &adv_data_cp);

				ret = hci_send_req(device, &adv_data_rq, 1000);
				if ( ret < 0 ) {
					hci_close_dev(device);
					perror("Failed to set advertising data.");

				}

				// Enable advertising.

				le_set_advertise_enable_cp advertise_cp;
				memset(&advertise_cp, 0, sizeof(advertise_cp));
				advertise_cp.enable = 0x01;

				struct hci_request enable_adv_rq = ble_hci_request(
					OCF_LE_SET_ADVERTISE_ENABLE,
					LE_SET_ADVERTISE_ENABLE_CP_SIZE, &status, &advertise_cp);

				ret = hci_send_req(device, &enable_adv_rq, 1000);
				if ( ret < 0 ) {
					hci_close_dev(device);
					perror("Failed to enable advertising.");

				}

				sub_input.clear();
				sequence += 1;
				delete []input_char;
			} 


			hci_close_dev(device);
			
			cout << "end of advertise" << endl;
			break;
		}
	}
	

	//pthread_exit(NULL);

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

	printf( "\n------thread %d------\n", (int)arg );

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
	while ( buf[19] != 0xB8 || buf[20] != 0x27 || buf[21] != 0xEB || buf[22] != 0xFC
			|| buf[23] != 0x24 || buf[24] != 0x91 ) {
		memset(&buf,0,sizeof(buf));
		len = read(device, buf, sizeof(buf));	
			}

	printf("\n");
	// Disable scanning.
	printf("...........\n");
	while ( 1 ) {
		
		printf("in while...\n");
		// if_count_bit_full(count_bit, packet_num) == false
		printf("vector size = %d\n", uint8_t_scan_vector.size());
		if (if_first_packet_received == false) {
			if ( buf[19] == 0xB8 && buf[20] == 0x27 && buf[21] == 0xEB && buf[22] == 0xFC && buf[23] == 0x24 
				&& buf[24] == 0x91 && buf[25] == 0x30 ) {
					
				printf("at 1...\n");
				total_len_in_scan = (int)buf[26];
				printf( "total_len : %d\n",total_len_in_scan );
				
				for ( int k = 0; k < total_len_in_scan; ++k ) {
					printf("push in vecotr\n");
					uint8_t_scan_vector.push_back(0x00);
				}

				printf( "receive first packet, and its length is %d",uint8_t_scan_vector.size() );				
				if (total_len_in_scan <= 18) {
					packet_num = 1;   
				}
				else {
					packet_num = 1 + ceil((float)(total_len_in_scan - 18)/19);
				}

				printf( "\n packet_num = %d", packet_num );				
				count_bit = new bool[packet_num];
				
				if ((int)buf[25]-48+1 == packet_num) {
					int begin_count = 27;
					int index_count = 0;
					while (index_count < total_len_in_scan) {
						uint8_t_scan_vector.at(index_count) = buf[begin_count++];
						++index_count;
					}
				}
				else {
					int begin_count = 27;
					int index_count = 0;
					while ( index_count < 18  ) {
						uint8_t_scan_vector.at(index_count) = buf[begin_count++];
						++index_count;
					}
				}
				
				count_bit[(int)buf[25] - 48] = true;
				if_first_packet_received = true;
				printf("\n end first packet\n");
				printf("\n (int)buf[25] - 48 = %d\n", (int)buf[25] -48);
				break;
			}	
		}
		else if ( buf[19] == 0xB8 && buf[20] == 0x27 && buf[21] == 0xEB && buf[22] == 0xFC && buf[23] == 0x24 
			&& buf[24] == 0x91 && buf[25] != 0x30 && if_first_packet_received == true && if_count_bit_full(count_bit, packet_num) == false ) {
				
			if ((int)buf[25] - 48 + 1 == packet_num) {
				printf( "\nit is the last packet\n");
				int begin_count = 26;
				int index_count = 0;
				int index_in_vector = 18 + ((int)buf[25] - 48 - 1)*19;
				while (index_in_vector < total_len_in_scan) {

					uint8_t_scan_vector.at(index_in_vector) = buf[begin_count];
					++begin_count;
					++index_in_vector;
				}
			}
			else {
				int begin_count = 26;
				int index_count = 0;

				int index_in_vector = 18 + ((int)buf[25]-48 - 1)*19;
				printf("\n(int)buf[25]-48-1*19 = %d\n", ((int)buf[25]-48-1)*19);


				while (index_count < 19) {
					uint8_t_scan_vector.at(index_in_vector) = buf[begin_count];
					index_count++;
					begin_count++;
					++index_in_vector;

				}
			}
			count_bit[(int)buf[25] -48] = true;
			for ( int l = 0; l < packet_num;++l ) {
				printf("%d",count_bit[l]);
			}
	
			break;
		}
		else if ( buf[19] == 0xB8 && buf[20] == 0x27 && buf[21] == 0xEB && buf[22] == 0xFC && buf[23] == 0x24 
			&& buf[24] == 0x91 && if_first_packet_received == true && if_count_bit_full(count_bit, packet_num) == true
			&& if_send == false ) {
			printf("\nstart to advertise......\n");
			advertise();
			printf("\nend of advertise\n");
					
			if_send = true;
		}
		
		memset(&buf,0,sizeof(buf));
		len = read(device, buf, sizeof(buf));
	
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


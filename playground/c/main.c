#include <stdio.h>
#include "reo_rs_ext.h"
#include "assert.h"

int main() {
	CProtoHandle proto = proto_create();
	CPutter a = reors_putter_claim(&proto, "A");
	CGetter b = reors_getter_claim(&proto, "B");

	int value = 42; // data to be sent
	int value2;     // data to be received

	void* from = (void*) &value; // indirection read by reo_rs
	void* to;                    // indirection written by reo_rs

	// send the message through the fifo buffer slot
	reors_putter_put_raw(&a, &from);
	reors_putter_get_raw(&b, &to);

	value2 = *((int *) to);
	assert(value == value2);

	// cleanup
	reors_putter_destroy(&a);
	reors_getter_destroy(&b);
	reors_proto_handle_destroy(&proto);

	printf("Everything went fine\n");

	return 0;
}
#include <stdio.h>
#include "reo_rs_ext.h"
#include "assert.h"

int main() {
	// create a protocol instance
	CProtoHandle proto = reors_generated_proto_create();

	// claim, initialize the logical ports "A" and "B" and bind them to variables.
	CPutter a = reors_putter_claim(&proto, "A");
	CGetter b = reors_getter_claim(&proto, "B");

	int value = 42; // data to be sent
	int value2;     // data to be received

	void* from = (void*) &value; // indirection read by reo_rs
	void* to;                    // indirection written by reo_rs

	// send the message from A to B py interacting with ports.
	/* put, get, destroy, claim functions are all thread-safe UNLESS they are
	   all performed on the same PORT. eg: `a` and `b` can be on different threads */
	reors_putter_put_raw(&a, &from);
	reors_putter_get_raw(&b, &to);

	// "local" computation of B. 
	value2 = *((int *) to);
	assert(value == value2);

	// cleanup. destroy ports and protocol handle (order is irrelevant).
	reors_putter_destroy(&a);
	reors_getter_destroy(&b);
	reors_proto_handle_destroy(&proto);

	printf("Everything went fine\n");
	return 0;
}
#include "../config.h"
#include "../../src/modules/msrp/msrp_parser.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	msrp_frame_t frame = {0};
	msrp_uri_t uri;
	str result;
	char *buf;

	if(size == 0 || size > MSRP_MAX_FRAME_SIZE) {
		return 0;
	}

	buf = (char *)malloc(size + 1);
	if(buf == NULL) {
		return 0;
	}
	memcpy(buf, data, size);
	buf[size] = '\0';

	frame.buf.s = buf;
	frame.buf.len = (int)size;

	if(msrp_parse_frame(&frame) == 0) {
		msrp_frame_get_sessionid(&frame, &result);
		msrp_frame_get_first_from_path(&frame, &result);

		for(msrp_hdr_t *hdr = frame.headers; hdr != NULL; hdr = hdr->next) {
			if(hdr->htype == MSRP_HDR_TO_PATH
					|| hdr->htype == MSRP_HDR_FROM_PATH
					|| hdr->htype == MSRP_HDR_USE_PATH) {
				msrp_parse_uri(hdr->body.s, hdr->body.len, &uri);
			}
		}
	}

	msrp_destroy_frame(&frame);
	free(buf);
	return 0;
}

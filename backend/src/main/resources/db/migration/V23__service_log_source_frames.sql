-- Link service-detail rows back to the packet that produced them, so the UI can jump to it.
--
-- packetNumber is now the tshark frame.number (see PcapParserService), so these frame columns can be
-- resolved to a stored packet/conversation.
--   dns_query_log.sample_frame      — frame.number of the first response packet for the aggregated query.
--   http_endpoint_log.request_frame — frame.number of the first request packet for the endpoint.
--   http_endpoint_log.response_frame— frame.number of the first response packet for the endpoint.
-- BIGINT to match packets.packet_number (Long) end-to-end.
ALTER TABLE dns_query_log
    ADD COLUMN sample_frame BIGINT;

ALTER TABLE http_endpoint_log
    ADD COLUMN request_frame  BIGINT,
    ADD COLUMN response_frame BIGINT;

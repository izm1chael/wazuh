# Native ingress qualification gate

At core RC2 base 0a951d08bafdd194af395ca67d923ed706d3df07:

* Azure Graph blob 2033a36969da859e95c73450da24f53d8e4c7ec4:
  updates min/max processing dates before send_message; recursively follows
  nextLink with HTTPS/host validation; request URLs and errors can be logged.
  A successful call cannot be equated to durable delivery, complete coverage,
  or a bounded end-to-end execution. Reuse the native integration content,
  not this watermark protocol without qualification.
* Azure utility 0cf89154077b2e1037215d571ce58dce0d9d9dc3:
  uses Unix datagram queue with 1:Azure: header; oversized message can be
  skipped and normal function return is not a durable receipt.
* Google subscriber f44d7e5aea28964466aef27baa212dfd1149aba8:
  acknowledges pulled messages after processing loop, including malformed
  JSON deliberately dropped. Distinguish transport ack, quarantine, and
  native ingestion ack; no silent conversion to successful WUCF delivery.

These observations are limited to exact inspected blobs. They are not a
claim that the existing integrations are generally insecure or unsupported.

## Required acceptance evidence before activation

1. Identify supported RC2 engine input and native integration binding; use
   existing WCS content and decoder paths. No direct event-index writing.
2. Establish explicit durability boundary and replay semantics. If no
   native durable receipt exists, use a separately reviewed durable ingress
   spool with retained events and reconciliation; do not label spool accept
   as WCS acceptance. If neither exists, block activation.
3. Prove stable source provenance and duplicate semantics through actual
   WCS findings, archives/indexing and error handling.
4. Test missing or incompatible content, schema drift, malformed and
   oversized records, sink restart, crash after delivery before cursor
   commit, duplicate retry and native processing failure.
5. Capture accepted, rejected, unknown and quarantined counts separately.
   An empty successful response never establishes telemetry coverage.
6. Verify egress and secret controls, native RBAC, retention and rollback
   before wiring service registration or the Dashboard activation action.

The Graph adapter candidate uses closed time windows with a lag and
explicit pagination; late arrivals beyond the lag need a designed overlap
and replay/deduplication policy. Provider-specific token expiry, API filters,
ordering, throttling and permissions require a live fixture gate.

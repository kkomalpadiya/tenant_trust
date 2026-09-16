import { createRequestAuditRecorder } from "@tenant-trust/api";

export function createVerificationRequestAuditRecorder(events = []) {
  if (!Array.isArray(events)) throw new TypeError("An audit event collection is required.");
  return createRequestAuditRecorder({
    async write(event) {
      events.push(event);
    },
  });
}

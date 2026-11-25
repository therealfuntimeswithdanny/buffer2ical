import type { FeedEvent } from "./types";

/** iCalendar requires CRLF line endings and lines folded at 75 octets. */
const LINE_LIMIT = 75;

function formatDateUTC(iso: string): string {
  const date = new Date(iso);
  const stamp = Number.isNaN(date.getTime()) ? new Date() : date;
  return stamp.toISOString().replace(/[-:]/g, "").split(".")[0] + "Z";
}

export function escapeICalText(value: unknown): string {
  return String(value ?? "")
    .replace(/\\/g, "\\\\")
    .replace(/\r\n|\r|\n/g, "\\n")
    .replace(/;/g, "\\;")
    .replace(/,/g, "\\,");
}

/** Escape a value placed inside a URI property (RFC 5545 URI values). */
function escapeICalUri(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/;/g, "\\;").replace(/,/g, "\\,");
}

export function foldICalLines(value: string): string {
  const encoder = new TextEncoder();
  return value
    .split("\n")
    .map(line => {
      let output = "";
      let chunk = "";
      let bytes = 0;
      for (const character of line) {
        const size = encoder.encode(character).length;
        if (bytes + size > LINE_LIMIT) {
          output += `${chunk}\r\n `;
          chunk = "";
          bytes = 1; // continuation whitespace counts toward the limit
        }
        chunk += character;
        bytes += size;
      }
      return output + chunk;
    })
    .join("\r\n");
}

export function generateICS(events: FeedEvent[], userId: string): string {
  const now = formatDateUTC(new Date().toISOString());

  let ics = [
    "BEGIN:VCALENDAR",
    "VERSION:2.0",
    "PRODID:-//Buffer2iCal//EN",
    "CALSCALE:GREGORIAN",
    "METHOD:PUBLISH",
    "X-WR-CALNAME:Buffer Scheduled Posts",
    "X-WR-TIMEZONE:UTC",
    // Ask calendar clients to re-fetch on the same cadence as the cron sync.
    "REFRESH-INTERVAL;VALUE=DURATION:PT5M",
    "X-PUBLISHED-TTL:PT5M",
    "",
  ].join("\n");

  for (const e of events) {
    const startMs = new Date(e.start).getTime();
    const dtStart = formatDateUTC(e.start);
    const dtEnd = formatDateUTC(new Date(startMs + 30 * 60000).toISOString());

    const preview = e.text.replace(/\s+/g, " ").trim();
    const summary = escapeICalText(
      `${e.channel} - ${preview.length > 30 ? preview.substring(0, 30) + "..." : preview}`,
    );

    const desc = escapeICalText(
      [
        "Status: SCHEDULED",
        `Channel: ${e.channel}`,
        `Profile: ${e.profileName}`,
        e.url ? `URL: ${e.url}` : "",
        e.text,
      ]
        .filter(Boolean)
        .join("\n"),
    );

    const lines = [
      "BEGIN:VEVENT",
      `UID:buffer-${e.id}-${userId}@buffer2ical`,
      `DTSTAMP:${now}`,
      `DTSTART:${dtStart}`,
      `DTEND:${dtEnd}`,
      `SUMMARY:${summary}`,
      `DESCRIPTION:${desc}`,
      e.url ? `URL:${escapeICalUri(e.url)}` : "",
      "STATUS:CONFIRMED",
      "TRANSP:OPAQUE",
      `CATEGORIES:SCHEDULED,${escapeICalText(e.channel.toUpperCase())}`,
      "END:VEVENT",
    ].filter(Boolean);

    ics += lines.join("\n") + "\n";
  }

  return foldICalLines(ics + "END:VCALENDAR");
}

export function generateEmptyICS(): string {
  return [
    "BEGIN:VCALENDAR",
    "VERSION:2.0",
    "PRODID:-//Buffer2iCal//EN",
    "CALSCALE:GREGORIAN",
    "METHOD:PUBLISH",
    "X-WR-CALNAME:Buffer Scheduled Posts",
    "END:VCALENDAR",
  ].join("\r\n");
}

export const CALENDAR_HEADERS: Record<string, string> = {
  "Content-Type": "text/calendar; charset=utf-8",
  "Content-Disposition": 'inline; filename="buffer.ics"',
  "Cache-Control": "public, max-age=300",
};

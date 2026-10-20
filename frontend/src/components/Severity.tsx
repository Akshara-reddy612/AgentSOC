import { Tooltip } from "@mantine/core";

export type Band = "critical" | "high" | "medium" | "low";

/** Review-queue priority -> band (the score is always shown next to the colour). */
export function band(priority: number): Band {
  if (priority >= 90) return "critical";
  if (priority >= 70) return "high";
  if (priority >= 40) return "medium";
  return "low";
}

export function SeverityPill({ priority, reasons }: { priority: number; reasons?: string[] }) {
  const b = band(priority);
  const label = `${b} priority (${priority})`;
  const pill = (
    <span className="soc-sev" data-band={b} aria-label={label}>
      {priority}
    </span>
  );
  if (!reasons) return pill;
  return (
    <Tooltip multiline w={420} withArrow label={[label, ...reasons].join("\n")} style={{ whiteSpace: "pre-line" }}>
      {pill}
    </Tooltip>
  );
}

export function SeverityStripe({ priority }: { priority: number }) {
  return <span className="soc-stripe" data-band={band(priority)} />;
}

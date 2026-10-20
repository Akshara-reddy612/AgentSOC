import cytoscape, { type Core, type ElementDefinition } from "cytoscape";
import { useEffect, useMemo, useRef } from "react";

type Row = Record<string, unknown>;

const ROLE_LABEL: Record<string, string> = { source_account: "account", source_host: "source", target_host: "target" };
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

/**
 * The case's entities: what the trusted fields say (host, account, addresses, programs) and what
 * each LLM hypothesis named.  A name the trusted fields do not support (entity binding "unbound")
 * is drawn red and dashed: the hypothesis may have been steered by text in the logs.
 * Labels are set as data (text), never as HTML.
 */
export default function EntityGraph({ trusted, hypotheses, checks, height = 300 }:
  { trusted: Row; hypotheses: Row[]; checks: Row[]; height?: number }) {
  const ref = useRef<HTMLDivElement>(null);
  const cy = useRef<Core | null>(null);

  const elements = useMemo(() => {
    const nodes = new Map<string, ElementDefinition>();
    const edges: ElementDefinition[] = [];
    const norm = (s: string) => s.trim().toLowerCase();
    const add = (name: unknown, kind: string, cls = "") => {
      const label = String(name ?? "").trim();
      if (!label || ["-", "unknown", "none", "n/a"].includes(norm(label))) return null;
      // one node per account whatever the domain prefix (BREACH\client2 = client2), as entity binding compares them
      const id = `${kind}:${kind === "account" ? norm(label).split("\\").pop() : norm(label)}`;
      if (!nodes.has(id)) nodes.set(id, { data: { id, label, kind }, classes: cls });
      return id;
    };
    const host = add(trusted.target_host ?? trusted.source_host, "host", "focus");
    const user = add(trusted.source_user, "account");
    if (host && user) edges.push({ data: { id: "e-user", source: user, target: host, label: "on" } });
    const key = Array.isArray(trusted.detector_key) ? (trusted.detector_key as unknown[]).map(String) : [];
    if (trusted.kind === "host" && key.length >= 3 && host) {
      const parent = add(key[1].split("\\").pop(), "program");
      const child = add(key[2].split("\\").pop(), "program");
      if (parent && child) {
        edges.push({ data: { id: "e-pc", source: parent, target: child, label: "started" } });
        edges.push({ data: { id: "e-ph", source: host, target: parent, label: "runs" } });
      }
    }
    const src = add(trusted.src_ip, "address");
    const dst = add(trusted.dst_ip ?? trusted.destination_ip, "address");
    if (src && dst) edges.push({ data: { id: "e-net", source: src, target: dst, label: String(trusted.dst_port ?? "") } });
    if (host && src && trusted.kind !== "host") edges.push({ data: { id: "e-hs", source: host, target: src, label: "is" } });

    hypotheses.forEach((h, i) => {
      const roles = (checks[i]?.binding_roles ?? {}) as Record<string, string>;
      const ids: Record<string, string | null> = {};
      for (const role of ["source_account", "source_host", "target_host"]) {
        const v = h[role];
        if (v == null || String(v).trim() === "") continue;
        const unbound = roles[role] === "unbound";
        const kind = role === "source_account" ? "account" : IPV4.test(String(v).trim()) ? "address" : "host";
        const id = add(v, kind, unbound ? "unbound" : "");
        if (id && unbound) nodes.get(id)!.classes = "unbound";
        ids[role] = id;
      }
      const s = ids.source_host ?? ids.source_account;
      const t = ids.target_host;
      if (s && t && s !== t) {
        const unbound = Object.values(roles).includes("unbound");
        edges.push({ data: { id: `h${i}`, source: s, target: t, label: String(h.technique_id ?? "") }, classes: unbound ? "hyp unbound" : "hyp" });
      }
      if (ids.source_account && ids.source_host && ids.source_account !== ids.source_host) {
        edges.push({ data: { id: `ha${i}`, source: ids.source_account, target: ids.source_host, label: ROLE_LABEL.source_account },
          classes: roles.source_account === "unbound" ? "hyp unbound" : "hyp" });
      }
    });
    return [...nodes.values(), ...edges];
  }, [trusted, hypotheses, checks]);

  useEffect(() => {
    if (!ref.current) return;
    cy.current?.destroy();
    cy.current = cytoscape({
      container: ref.current,
      elements,
      userZoomingEnabled: false,
      style: [
        {
          selector: "node",
          style: {
            label: "data(label)", "font-size": 12, color: "#e6ebf2", "text-valign": "bottom", "text-margin-y": 5,
            "text-wrap": "ellipsis", "text-max-width": "140px",
            "text-background-color": "#111a2b", "text-background-opacity": 0.85, "text-background-padding": "2px",
            width: 22, height: 22, "background-color": "#33435e", "border-width": 2, "border-color": "#7b8798",
          },
        },
        { selector: "node[kind = 'host']", style: { shape: "round-rectangle", "background-color": "#1c2a45", "border-color": "#22d3ee" } },
        { selector: "node[kind = 'account']", style: { shape: "ellipse", "border-color": "#a8b3c4" } },
        { selector: "node[kind = 'program']", style: { shape: "diamond", "border-color": "#7b8798" } },
        { selector: "node[kind = 'address']", style: { shape: "hexagon", "border-color": "#7b8798" } },
        { selector: "node.focus", style: { width: 30, height: 30, "border-width": 3 } },
        { selector: "node.unbound", style: { "border-color": "#d03b3b", "border-style": "dashed", "border-width": 3, color: "#ff8a8a" } },
        {
          selector: "edge",
          style: {
            width: 1.5, "curve-style": "bezier", "line-color": "#46566f", "target-arrow-shape": "triangle",
            "target-arrow-color": "#46566f", "arrow-scale": 0.8, label: "data(label)", "font-size": 10, color: "#7b8798",
            "text-rotation": "autorotate", "text-background-color": "#111a2b", "text-background-opacity": 1,
            "text-background-padding": "1px",
          },
        },
        { selector: "edge.hyp", style: { "line-color": "#a78bfa", "target-arrow-color": "#a78bfa", "line-style": "solid", color: "#a78bfa" } },
        { selector: "edge.unbound", style: { "line-color": "#d03b3b", "target-arrow-color": "#d03b3b", "line-style": "dashed", color: "#ff8a8a" } },
      ],
      // the alert's host in the middle, what it touches around it, LLM-named entities outside
      layout: {
        name: "concentric", animate: false, padding: 28, minNodeSpacing: 34, startAngle: (3 / 2) * Math.PI,
        concentric: (n: cytoscape.NodeSingular) => (n.hasClass("focus") ? 3 : n.hasClass("unbound") ? 1 : 2),
        levelWidth: () => 1,
      },
    });
    cy.current.fit(undefined, 28);
    if (cy.current.zoom() > 1.3) {
      cy.current.zoom(1.3);
      cy.current.center();
    }
    return () => {
      cy.current?.destroy();
      cy.current = null;
    };
  }, [elements]);

  return <div ref={ref} style={{ height, width: "100%" }} aria-label="Entity graph of the case" role="img" />;
}

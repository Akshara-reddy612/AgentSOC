import cytoscape, { type Core } from "cytoscape";
import { useEffect, useRef } from "react";
import type { GraphData } from "../api";
import { PROVENANCE_COLOR } from "../format";

const NODE_COLOR: Record<string, string> = { host: "#ff922b", image: "#74c0fc", account: "#b197fc", script: "#ffe066" };

/** What the store has learned around one host. Labels are set as data (text), never as HTML. */
export default function Graph({ data, height = 460 }: { data: GraphData; height?: number }) {
  const ref = useRef<HTMLDivElement>(null);
  const cy = useRef<Core | null>(null);

  useEffect(() => {
    if (!ref.current) return;
    cy.current?.destroy();
    cy.current = cytoscape({
      container: ref.current,
      elements: [
        ...data.nodes.map((n) => ({ data: { id: n.id, label: n.label, kind: n.type } })),
        ...data.edges.map((e, i) => ({ data: { id: `e${i}`, source: e.source, target: e.target, prov: e.learned_from, label: e.type } })),
      ],
      style: [
        {
          selector: "node",
          style: {
            label: "",
            "font-size": 18,
            color: "#e9ecef",
            "text-valign": "bottom",
            "text-margin-y": 6,
            "text-background-color": "#1a1b1e",
            "text-background-opacity": 0.8,
            "text-background-padding": "2px",
            width: (n: cytoscape.NodeSingular) => Math.min(30, 8 + 3 * n.degree(false)),
            height: (n: cytoscape.NodeSingular) => Math.min(30, 8 + 3 * n.degree(false)),
            "background-color": (n: cytoscape.NodeSingular) => NODE_COLOR[String(n.data("kind"))] ?? "#868e96",
          },
        },
        { selector: "node.hub, node.hover, node[kind = 'host']", style: { label: "data(label)" } },
        { selector: "node[kind = 'host']", style: { "border-width": 3, "border-color": "#ffffff" } },
        {
          selector: "edge",
          style: {
            width: 1.5,
            "curve-style": "bezier",
            "target-arrow-shape": "triangle",
            "arrow-scale": 0.7,
            "line-color": (e: cytoscape.EdgeSingular) => PROVENANCE_COLOR[String(e.data("prov"))] ?? "#868e96",
            "target-arrow-color": (e: cytoscape.EdgeSingular) => PROVENANCE_COLOR[String(e.data("prov"))] ?? "#868e96",
          },
        },
      ],
      layout: { name: "cose", animate: false, nodeRepulsion: () => 400000, idealEdgeLength: () => 70, gravity: 0.25, padding: 24 },
    });
    cy.current.nodes().filter((n) => n.degree(false) >= 4).addClass("hub");
    cy.current.on("mouseover", "node", (e) => e.target.addClass("hover"));
    cy.current.on("mouseout", "node", (e) => e.target.removeClass("hover"));
    return () => {
      cy.current?.destroy();
      cy.current = null;
    };
  }, [data]);

  return <div ref={ref} style={{ height, width: "100%", border: "1px solid var(--mantine-color-dark-4)", borderRadius: 8 }} />;
}
